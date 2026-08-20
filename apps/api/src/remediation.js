export function buildRemediationPlan({ packageName, version, ecosystem, targetVersion, advisoryId = '', fileName = '' }) {
  const target = String(targetVersion || '').trim();
  if (!target) return { status: 'needs-review', packageName, version, ecosystem, advisoryId, reason: 'No fixed version was published by the advisory or registry.', actions: [] };
  const commands = {
    npm: `npm install --save-exact ${packageName}@${target}`,
    pypi: `python -m pip install --upgrade ${packageName}==${target}`,
    cargo: `cargo update -p ${packageName} --precise ${target}`,
    go: `go get ${packageName}@${target} && go mod tidy`,
    maven: `mvn versions:use-dep-version -Dincludes=${packageName} -DnewVersion=${target}`
  };
  const files = {
    npm: fileName || 'package.json + package-lock.json',
    pypi: fileName || 'requirements.txt / pyproject.toml lockfile',
    cargo: fileName || 'Cargo.toml + Cargo.lock',
    go: fileName || 'go.mod + go.sum',
    maven: fileName || 'pom.xml'
  };
  return {
    status: 'ready-for-review', packageName, ecosystem, fromVersion: version, targetVersion: target, advisoryId,
    files: [files[ecosystem] || fileName || 'dependency manifest'],
    actions: [{ label: 'Update dependency', command: commands[ecosystem] || `Update ${packageName} to ${target}` }, { label: 'Regenerate evidence', command: 'Upload the updated dependency file to Radius and rescan advisories.' }],
    pullRequest: { supported: Boolean(process.env.RADIUS_GITHUB_TOKEN || process.env.GITHUB_TOKEN), automaticCreation: false, reason: 'Radius prepares the exact upgrade plan; repository mutation requires an explicit GitHub action.' }
  };
}
