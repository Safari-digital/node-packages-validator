export default class Logger {
    /**
     * Start a trace process
     * @param {string} processId Unique identifier for the process
     * @param {string} message Initial message to log (optional)
     */
    static startTrace(processId, message) {
        Logger.logStack[processId] = [];
        Logger.logStack[processId].push(Logger.separator);
        Logger.logStack[processId].push(`[${processId}] ${message ?? 'Starting process...'}`);
    }

    /**
     * End a trace process and output the log
     * @param {string} processId Unique identifier for the process
     */
    static endTrace(processId) {
        if (!Logger.logStack[processId]) {
            return;
        }
        Logger.logStack[processId].push(Logger.separator);
        for (const line of Logger.logStack[processId]) {
            if (Array.isArray(line)) {
                console.log(...line);
            } else {
                console.log(line);
            }
        }
        delete Logger.logStack[processId];
    }

    /**
     * Log a message in the trace process
     * @param {string} processId Unique identifier for the process
     * @param {string} message Message to log
     * @param {'success'|'warning'|'critical'} type Type of message for coloring (optional)
     */
    static trace(processId, message, type) {
        if (Logger.logStack[processId]) {
            Logger.logStack[processId].push(
                Logger.traceTypes[type]
                    ? [Logger.traceTypes[type], `[${processId}] ${message}`]
                    : `[${processId}] ${message}`,
            );
        }
    }

    /**
     * Log a critical message in the trace process
     * @param {string} processId Unique identifier for the process
     * @param {string} message Message to log
     */
    static traceCritical = (processId, message) => Logger.trace(processId, message, 'critical');

    /**
     * Log a warning message in the trace process
     * @param {string} processId Unique identifier for the process
     * @param {string} message Message to log
     */
    static traceWarning = (processId, message) => Logger.trace(processId, message, 'warning');

    /**
     * Log a success message in the trace process
     * @param {string} processId Unique identifier for the process
     * @param {string} message Message to log
     */
    static traceSuccess = (processId, message) => Logger.trace(processId, message, 'success');

    /**
     * Log a separator line in the trace process
     * @param {string} processId Unique identifier for the process
     * @returns
     */
    static traceSeparator = processId => Logger.trace(processId, Logger.separator);

    static separator = '----------------------------------------------------------------';
    static logStack = {};
    static traceTypes = {
        success: '\x1b[32m%s\x1b[0m',
        warning: '\x1b[33m%s\x1b[0m',
        critical: '\x1b[31m%s\x1b[0m',
    };
}
