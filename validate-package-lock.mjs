#!/usr/bin/env node
import PackageLock from './PackageLock.mjs';

process.exitCode = (await PackageLock.validateAsync()) > 0 ? 1 : 0;
