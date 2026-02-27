import NIO
import NIOSSH

/// Error thrown when an SSH keepalive request times out (no response from server).
public enum SSHKeepAliveError: Error {
    case timeout
}

extension SSHClient {
    /// Sends an SSH `keepalive@openssh.com` global request with `wantReply: true`.
    ///
    /// The timeout is handled at the NIO event loop level using `scheduleTask`.
    /// This is critical because NIO `EventLoopFuture`s do NOT respond to Swift
    /// structured concurrency cancellation — a `withThrowingTaskGroup` timeout
    /// would hang indefinitely on a zombie TCP connection (the exact scenario
    /// we need to detect).
    ///
    /// - Parameter timeout: How long to wait for a server response before
    ///   throwing `SSHKeepAliveError.timeout`. Default: 10 seconds.
    /// - Throws: `SSHKeepAliveError.timeout` if the server doesn't respond in time.
    ///   Other errors if the server rejects the request or the connection is closed.
    ///
    /// This method is thread-safe: it dispatches onto the connection's event loop.
    public func sendKeepAlive(timeout: TimeAmount = .seconds(10)) async throws {
        try await eventLoop.flatSubmit { [session = self.session] in
            let resultPromise = self.eventLoop.makePromise(of: Void.self)
            var completed = false  // Safe: only accessed from this event loop thread

            // Send the keepalive global request
            let responsePromise = self.eventLoop.makePromise(of: ByteBuffer?.self)
            session.sshHandler.value.sendGlobalRequest(
                type: "keepalive@openssh.com",
                wantReply: true,
                promise: responsePromise
            )

            // Schedule timeout on the event loop — fires if server doesn't respond
            let timeoutTask = self.eventLoop.scheduleTask(in: timeout) {
                guard !completed else { return }
                completed = true
                resultPromise.fail(SSHKeepAliveError.timeout)
            }

            // When server responds (success or rejection), cancel the timeout
            responsePromise.futureResult.whenComplete { result in
                timeoutTask.cancel()
                guard !completed else { return }
                completed = true
                switch result {
                case .success:
                    resultPromise.succeed(())
                case .failure(let error):
                    resultPromise.fail(error)
                }
            }

            return resultPromise.futureResult
        }.get()
    }

    /// Enables TCP-level SO_KEEPALIVE on the underlying socket.
    /// This is a low-level safety net — the OS will probe dead connections
    /// even if the SSH-level keepalive is not running.
    public func enableTCPKeepAlive() async throws {
        try await session.channel.setOption(
            ChannelOptions.socketOption(.so_keepalive),
            value: 1
        ).get()
    }
}
