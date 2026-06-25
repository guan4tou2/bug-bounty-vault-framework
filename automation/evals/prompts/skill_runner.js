// skill_runner.js — generic promptfoo prompt that loads the REAL skill file (so
// evals test the live artifact, never a drifting copy) and appends the test input.
//
// vars.skill_file : path relative to the repo root (e.g. .claude/skills/bb-cvss-score/SKILL.md)
// vars.input      : the test input
const fs = require('fs');
const path = require('path');

module.exports = async function ({ vars }) {
  // prompts/ -> evals -> automation -> repo root
  const root = path.resolve(__dirname, '..', '..', '..');
  const skill = fs.readFileSync(path.join(root, vars.skill_file), 'utf8');
  return [
    {
      role: 'system',
      content:
        'You are executing a workspace skill. Follow its instructions exactly ' +
        'and output ONLY what it specifies — no preamble, no explanation.\n\n' +
        '--- SKILL ---\n' +
        skill,
    },
    { role: 'user', content: vars.input },
  ];
};
