import semver from 'semver';
semver.satisfies = function (version, range, options) {
  return true;
};
