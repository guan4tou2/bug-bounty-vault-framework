// Reusable Playwright-CLI acceptance driver for the owned loopback fixture only.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

async function browserFlow(page, config) {
  await page.context().route('**/*', route => new URL(route.request().url()).origin === config.url
    ? route.continue() : route.abort());
  const results = [];
  for (const branch of ['test', 'control']) {
    await page.goto(config.url + '/');
    if (await page.title() !== 'Owned Sharing Lab') throw new Error('Not the owned fixture');
    await page.locator('body').ariaSnapshot();
    await page.getByRole('textbox', { name: 'Trace ID' }).fill(config.prefix + '-' + branch);
    await page.getByRole('combobox', { name: 'Branch' }).selectOption(branch);
    await page.getByRole('combobox', { name: 'Runner' }).selectOption(config.runner);
    await page.getByRole('button', { name: 'Start trace', exact: true }).click();
    const click = async name => {
      await page.locator('body').ariaSnapshot();
      const button = page.getByRole('button', { name, exact: true });
      if (!await button.isVisible()) throw new Error('Missing visible control: ' + name);
      await button.click();
    };
    const read = async name => {
      await page.locator('body').ariaSnapshot();
      const link = page.getByRole('link', { name, exact: true });
      if (!await link.isVisible()) throw new Error('Missing visible link');
      const [response] = await Promise.all([
        page.waitForResponse(r => r.url().startsWith(config.url + '/document/')), link.click()]);
      const content = await page.locator('body').innerText();
      return { status: response.status(), cache: response.headers()['cache-control'],
        protected: content.includes('SYNTHETIC PRIVATE DOCUMENT') };
    };
    await click('Create document');
    await click('Share with recipient');
    await click('Use recipient');
    const normal = await read('Open remembered document link');
    if (normal.status !== 200 || !normal.protected) throw new Error('Normal UI baseline failed');
    await page.getByRole('link', { name: 'Back to workflow', exact: true }).click();
    await click('Use owner');
    await click('Revoke share');
    await click(branch === 'test' ? 'Use recipient' : 'Use stranger');
    const after = await read(branch === 'test' ? 'Open remembered document link' : 'Open harness-provided CONTROL link');
    if (after.status !== (branch === 'test' ? 200 : 403) || after.cache !== 'no-store') {
      throw new Error('Fresh server comparison failed');
    }
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.screenshot({ path: config.root + '/' + config.prefix + '-' + branch + '.png', fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: config.root + '/' + config.prefix + '-' + branch + '-mobile.png', fullPage: true });
    await page.getByRole('link', { name: 'Back to workflow', exact: true }).click();
    await click('Finish trace');
    results.push({ branch, normal, after, completed: true });
  }
  return { fixture_only: true, storage_session: config.session, runner: config.runner, results };
}

const [rootArg, session = 'vault-flow-replay', prefix = 'replay'] = process.argv.slice(2);
if (!rootArg || !/^[a-z][a-z0-9-]+$/.test(session) || !['source', 'replay'].includes(prefix)) {
  throw new Error('Usage: node run_sharing_ui.cjs <owned-lab-root> [isolated-session] [source|replay]');
}
const root = path.resolve(rootArg);
const server = JSON.parse(fs.readFileSync(path.join(root, 'server.json'), 'utf8'));
const url = new URL(server.url);
if (!server.fixture_only || url.hostname !== '127.0.0.1' || !url.port) throw new Error('Loopback fixture required');
const receipt = path.join(root, prefix + '-browser-receipt.txt');
if (fs.existsSync(receipt)) throw new Error('Refusing to overwrite prior browser evidence');
const wrapper = path.join(require('node:os').homedir(), '.codex/skills/playwright/scripts/playwright_cli.sh');
const run = args => execFileSync(wrapper, ['--session=' + session, ...args], { encoding: 'utf8', timeout: 120000 });
run(['open', 'about:blank', '--headed']);
run(['snapshot', '--json']);
const config = { root, session, prefix, runner: prefix + '-browser', url: server.url };
const result = run(['run-code', `async page => (${browserFlow.toString()})(page, ${JSON.stringify(config)})`]);
fs.writeFileSync(receipt, result, { flag: 'wx' });
process.stdout.write(result);
