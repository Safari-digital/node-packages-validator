import fs from "fs";
import Logger from "./Logger.mjs";

export default class PackageLock {
  /**
   * Get the content of package-lock.json
   * @returns {Object}
   */
  static getPackageLock = () =>
    JSON.parse(fs.readFileSync("package-lock.json", "utf8"));

  /**
   * Get the list of infected packages
   * See https://github.com/DataDog/malicious-software-packages-dataset for further information
   * @returns {Promise<{[string]: null | Array<string> }>}
   */
  static async getCompromisedPackagesAsync() {
    const source =
      "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/refs/heads/main/samples/npm/manifest.json";
    const response = await fetch(source);
    return await response.json();
  }

  /**
   * Create an index of all packages in the package-lock.json
   * @returns {Object}
   */

  static indexPackages() {
    const lock = this.getPackageLock();
    const deps = lock.packages ?? lock.dependencies ?? {};
    const index = {};

    function scan(obj) {
      for (const [name, data] of Object.entries(obj)) {
        if (data) {
          index[name] = data;
          if (data.dependencies) scan(data.dependencies);
        }
      }
    }

    scan(deps);
    return index;
  }
  /**
   * Validate packages based on the compromisedPackages list
   * @returns {Promise<void>}
   */
  static async validateAsync() {
    const processId = "PACKAGE-LOCK-VALIDATION";
    let errorCount = 0;

    console.log(`[${processId}]`, "Starting package-lock.json validation...");
    Logger.startTrace(processId, "package-lock.json validation result:");

    const compromisedList = await this.getCompromisedPackagesAsync();
    const packageIndex = this.indexPackages();

    const compromisedSet = new Set(Object.keys(compromisedList));
    const installedSet = new Set(Object.keys(packageIndex));

    const intersection = [...installedSet].filter((pkg) =>
      compromisedSet.has(pkg)
    );

    for (const pkg of intersection) {
      const data = packageIndex[pkg];
      const versions = compromisedList[pkg];
      if (!data || !data.version) continue;

      const resolved = data.resolved ?? "";

      if (!versions) {
        Logger.traceWarning(
          processId,
          `${pkg} => compromised package found!!! (${data.version} - ${resolved})`
        );
        errorCount++;
        continue;
      }

      const versionSet = new Set(versions);
      if (
        versionSet.has(data.version) ||
        versions.some((v) => resolved.includes(`-${v}.tgz`))
      ) {
        Logger.traceWarning(
          processId,
          `${pkg} => ${data.version} compromised version found!!! (${resolved})`
        );
        errorCount++;
      }
    }

    if (errorCount === 0) {
      Logger.traceSuccess(
        processId,
        `No vulnerability found in package-lock.json`
      );
    } else {
      Logger.traceCritical(processId, `${errorCount} vulnerability(ies) found`);
      Logger.traceCritical(
        processId,
        `Please remove your package-lock.json file and node_modules folder, clean your npm cache using 'npm cache clean --force' and fix your package.json dependencies before reinstalling everything using 'npm install'`
      );
    }
    Logger.endTrace(processId);
  }
}