"""Scanner-specific exceptions for graceful degradation."""


class ScannerError(Exception):
    pass


class ToolUnavailableError(ScannerError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(f"Tool '{tool_name}' is not installed or not in PATH")
        self.tool_name = tool_name


class SubprocessTimeoutError(ScannerError):
    def __init__(self, tool_name: str, timeout: int) -> None:
        super().__init__(f"Tool '{tool_name}' timed out after {timeout}s")
        self.tool_name = tool_name


class ScannerExecutionError(ScannerError):
    def __init__(self, tool_name: str, returncode: int, stderr: str) -> None:
        super().__init__(f"Tool '{tool_name}' exited with code {returncode}: {stderr[:200]}")
        self.tool_name = tool_name
        self.returncode = returncode
