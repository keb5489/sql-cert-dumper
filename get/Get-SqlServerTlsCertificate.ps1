<#
.SYNOPSIS
    Retrieves the TLS certificate a SQL Server instance presents, using only
    a TCP connection to port 1433. No SQL credentials or database access
    required -- the handshake stops before the login packet is ever sent.

.DESCRIPTION
    SQL Server has no dedicated TLS port. Encryption is negotiated inline on
    the standard TDS port, STARTTLS-style:

        1. Client sends a plaintext TDS Pre-Login packet (type 0x12)
           advertising ENCRYPTION = ENCRYPT_ON.
        2. Server replies with its own Pre-Login packet (type 0x04) stating
           which encryption mode applies.
        3. The same TCP connection is upgraded to TLS. The server presents
           its certificate here -- which is all this script needs.
        4. (Not performed) A LOGIN7 packet with credentials would follow.

    TDS ENCAPSULATION OF THE HANDSHAKE
    During step 3 the TLS handshake records are not written raw onto the
    socket. Per MS-TDS they travel inside TDS packets of type 0x12:

        [8-byte TDS header][TLS handshake bytes]

    The server's ServerHello/Certificate flight comes back wrapped the same
    way and must have those headers stripped before reaching the TLS engine.
    A single flight may span several TDS packets. Only once the handshake
    completes does the TLS record layer own the wire directly; from then on
    TDS packets travel inside TLS rather than the other way around.

    TdsPreloginTlsStream (below) implements exactly this: it sits between
    SslStream and the socket, framing outbound handshake writes and
    unframing inbound ones, then switching to passthrough when done.

    MAINTENANCE WARNING: do not "simplify" this by handing SslStream the
    NetworkStream directly. The server would receive an unframed ClientHello,
    fail to recognize a TDS packet, and never reply -- the connection hangs
    at the handshake with no error, which is a slow thing to diagnose.

    ENCRYPTION MODES
    The client always requests ENCRYPT_ON, so retrieval works whether or not
    the server has "Force Encryption" enabled. The server's answer is parsed
    and reported so you can tell which configuration you are looking at:

        0x00 ENCRYPT_OFF      Force Encryption OFF. Normally only the login
                              packet would be encrypted, but the full-stream
                              upgrade still happens because we asked for it.
        0x01 ENCRYPT_ON       Server encrypts because the client requested it.
        0x02 ENCRYPT_NOT_SUP  Server cannot do TLS at all. No certificate
                              exists to retrieve; the script stops rather
                              than retrying other TLS versions.
        0x03 ENCRYPT_REQ      Force Encryption ON. TLS is mandatory for the
                              whole connection regardless of client request.

    SECURITY NOTE
    Certificate validation is deliberately bypassed (the callback accepts
    unconditionally) so that self-signed, expired, or hostname-mismatched
    certificates can still be inspected -- which is the entire point of a
    retrieval tool. Nothing here establishes trust, and no credentials are
    transmitted. Do not copy this validation callback into code that
    actually connects to a database.

.PARAMETER ServerName
    Hostname or IP of the SQL Server. Also sent as the TLS SNI name, so
    prefer the name clients actually connect with when checking a
    hostname-specific certificate.

.PARAMETER Port
    TCP port. Defaults to 1433. For a named instance on a static port, pass
    that port directly; this script does not query SQL Browser (UDP 1434).

.PARAMETER OutFile
    Where to write the retrieved certificate, DER-encoded (.cer).

.PARAMETER TimeoutMs
    Wall-clock cap per handshake attempt. Prevents an indefinite hang when a
    server or intermediate device accepts the connection but never completes
    the TLS upgrade. Default 15000.

.EXAMPLE
    .\Get-SqlServerCert.ps1 -ServerName sqlbox01.contoso.com

.EXAMPLE
    .\Get-SqlServerCert.ps1 -ServerName 10.20.30.40 -Port 1433 -OutFile .\prod-sql.cer

.NOTES
    Requires Windows PowerShell 5.1 or later. Works fully offline: Add-Type
    compiles the helper classes with the C# compiler bundled with the .NET
    Framework, so no internet access or NuGet restore is involved.

    Reference: MS-TDS section 2.2.6.5 (PRELOGIN) and the encryption
    negotiation described in MS-TDS 3.3.5.5.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [int]$Port = 1433,

    [string]$OutFile = ".\sqlserver_cert.cer",

    [int]$TimeoutMs = 15000
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helper types, compiled once per session.
#
# These are C# rather than PowerShell classes because SslStream invokes both
# of them on thread-pool threads during the async handshake. PowerShell code
# cannot run on a thread with no Runspace attached; compiled types have no
# such constraint.
#
# The C# below is deliberately limited to C# 5 syntax (no expression-bodied
# members, string interpolation, or null-conditional operators) so it
# compiles under the CodeDom compiler that Windows PowerShell 5.1 uses.
# ---------------------------------------------------------------------------
if (-not ('TdsPreloginTlsStream' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Supplies SslStream's certificate validation callback, and records the
/// certificate the server presented.
///
/// Validation always succeeds: this tool exists to retrieve certificates,
/// including self-signed or expired ones that a validating client would
/// reject. No trust decision is made and no credentials are sent.
///
/// Capturing in the callback rather than relying solely on
/// SslStream.RemoteCertificate means the certificate is available even when
/// the handshake later fails, which makes diagnostics possible.
/// </summary>
public static class TdsCertCapture
{
    /// <summary>Certificate seen by the most recent validation callback.</summary>
    public static X509Certificate Captured;

    public static bool AcceptAll(object sender, X509Certificate certificate,
                                 X509Chain chain, SslPolicyErrors errors)
    {
        Captured = certificate;
        return true;
    }

    public static RemoteCertificateValidationCallback Callback
    {
        get { return new RemoteCertificateValidationCallback(AcceptAll); }
    }

    /// <summary>Clear state before an attempt, so a stale cert cannot be reused.</summary>
    public static void Reset() { Captured = null; }
}

/// <summary>
/// Adapts a raw socket stream into the TDS framing that SQL Server expects
/// during the pre-login TLS handshake. Sits between SslStream and the
/// NetworkStream.
///
/// While the handshake is in progress:
///   Write - prefixes an 8-byte TDS PRELOGIN (0x12) header, emitting the
///           caller's bytes as one TDS packet.
///   Read  - reads one TDS packet and returns only its payload, discarding
///           the header. SslStream calls Read repeatedly until it has a
///           complete TLS record, so a handshake flight spread over several
///           TDS packets (a large certificate chain, typically) reassembles
///           without any special handling here.
///
/// After CompleteHandshake() the class is a pure passthrough, because the
/// TLS record layer then addresses the wire directly.
///
/// Only the synchronous Read/Write are overridden. Stream's base class
/// implements the async variants on top of them, which is sufficient here
/// and keeps the framing logic in one place.
/// </summary>
public class TdsPreloginTlsStream : Stream
{
    private readonly Stream _inner;
    private bool _handshakeComplete;

    // Payload of the TDS packet currently being handed out, plus how much of
    // it the caller has already taken. A single packet usually satisfies
    // several Read calls.
    private byte[] _payload = new byte[0];
    private int _payloadPos;

    public TdsPreloginTlsStream(Stream inner) { _inner = inner; }

    /// <summary>
    /// Stop framing and pass bytes through untouched. Call once the TLS
    /// handshake has completed successfully.
    /// </summary>
    public void CompleteHandshake() { _handshakeComplete = true; }

    public override bool CanRead  { get { return true;  } }
    public override bool CanWrite { get { return true;  } }
    public override bool CanSeek  { get { return false; } }

    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position
    {
        get { throw new NotSupportedException(); }
        set { throw new NotSupportedException(); }
    }

    public override void Flush() { _inner.Flush(); }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_handshakeComplete)
        {
            _inner.Write(buffer, offset, count);
            _inner.Flush();
            return;
        }

        // TDS header layout (all multi-byte fields big-endian):
        //   [0] Type, [1] Status, [2..3] Length INCLUDING this header,
        //   [4..5] SPID, [6] PacketID, [7] Window.
        // Length counts the header itself, hence count + 8.
        int total = count + 8;
        byte[] packet = new byte[total];
        packet[0] = 0x12;                          // Type: PRELOGIN
        packet[1] = 0x01;                          // Status: EOM, this is the whole message
        packet[2] = (byte)((total >> 8) & 0xFF);   // Length, high byte
        packet[3] = (byte)(total & 0xFF);          // Length, low byte
        packet[4] = 0x00; packet[5] = 0x00;        // SPID: unused by the client
        packet[6] = 0x00;                          // PacketID
        packet[7] = 0x00;                          // Window
        Buffer.BlockCopy(buffer, offset, packet, 8, count);

        _inner.Write(packet, 0, total);
        _inner.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_handshakeComplete)
            return _inner.Read(buffer, offset, count);

        // Hand back the remainder of the packet already in flight, if any.
        if (_payloadPos < _payload.Length)
        {
            int give = Math.Min(_payload.Length - _payloadPos, count);
            Buffer.BlockCopy(_payload, _payloadPos, buffer, offset, give);
            _payloadPos += give;
            return give;
        }

        // Current packet is exhausted; pull the next one off the wire.
        byte[] header = new byte[8];
        if (!ReadExact(header, 8)) return 0;

        int totalLen = (header[2] << 8) | header[3];
        int payloadLen = totalLen - 8;
        if (payloadLen < 0)
            throw new IOException("Malformed TDS packet: declared length " + totalLen + " is shorter than its header.");
        if (payloadLen == 0)
            return 0;

        byte[] payload = new byte[payloadLen];
        if (!ReadExact(payload, payloadLen)) return 0;

        _payload = payload;
        _payloadPos = 0;

        int n = Math.Min(payloadLen, count);
        Buffer.BlockCopy(_payload, 0, buffer, offset, n);
        _payloadPos = n;
        return n;
    }

    /// <summary>
    /// Fills exactly 'need' bytes, looping because a single socket read may
    /// return fewer. Returns false if the peer closed the connection first.
    /// </summary>
    private bool ReadExact(byte[] target, int need)
    {
        int got = 0;
        while (got < need)
        {
            int r = _inner.Read(target, got, need - got);
            if (r == 0) return false;
            got += r;
        }
        return true;
    }
}
'@
}

function Build-PreLoginPacket {
    <#
        Builds the client's Pre-Login packet.

        A PRELOGIN message is an options table followed by the option data:

            [5 bytes per option][0xFF terminator][option data...]

        Each table entry is (Token, OffsetHi, OffsetLo, LengthHi, LengthLo),
        where Offset points at that option's bytes measured from the start of
        the payload -- i.e. just past the 8-byte TDS header. Offsets are
        therefore computed only after the table's own size is known.

        The option values themselves are mostly placeholders. Only ENCRYPTION
        matters for certificate retrieval; the rest are present because the
        server expects a well-formed table.
    #>

    $version    = [byte[]](0x09,0x00,0x00,0x00,0x00,0x00)  # Claimed client version; any plausible value works
    $encryption = [byte[]](0x01)                           # ENCRYPT_ON: request a TLS upgrade
    $instopt    = [byte[]](0x00)                           # Instance name: empty string (just its null terminator)
    $threadid   = [byte[]](0x00,0x00,0x00,0x00)            # Client thread id, informational only
    $mars       = [byte[]](0x00)                           # Multiple Active Result Sets: off

    $optionDefs = @(
        @{ Token = 0x00; Data = $version    },  # VERSION
        @{ Token = 0x01; Data = $encryption },  # ENCRYPTION
        @{ Token = 0x02; Data = $instopt    },  # INSTOPT
        @{ Token = 0x03; Data = $threadid   },  # THREADID
        @{ Token = 0x04; Data = $mars       }   # MARS
    )

    # Data begins immediately after the table: 5 bytes per entry, plus the
    # single 0xFF terminator byte.
    $headerLen = ($optionDefs.Count * 5) + 1
    $offset = $headerLen

    $optionHeaderBytes = [System.Collections.Generic.List[byte]]::new()
    $dataBytes         = [System.Collections.Generic.List[byte]]::new()

    foreach ($opt in $optionDefs) {
        $len = $opt.Data.Length
        $optionHeaderBytes.Add([byte]$opt.Token)
        $optionHeaderBytes.Add([byte](($offset -shr 8) -band 0xFF))
        $optionHeaderBytes.Add([byte]($offset -band 0xFF))
        $optionHeaderBytes.Add([byte](($len -shr 8) -band 0xFF))
        $optionHeaderBytes.Add([byte]($len -band 0xFF))
        $dataBytes.AddRange([byte[]]$opt.Data)
        $offset += $len
    }
    $optionHeaderBytes.Add([byte]0xFF)  # End of the options table

    $payload = [System.Collections.Generic.List[byte]]::new()
    $payload.AddRange($optionHeaderBytes)
    $payload.AddRange($dataBytes)

    # Length in the TDS header counts the header itself.
    $totalLen = 8 + $payload.Count

    $header = [byte[]](
        0x12,                                   # Type: PRELOGIN
        0x01,                                   # Status: EOM, single packet
        [byte](($totalLen -shr 8) -band 0xFF),  # Length, high byte
        [byte]($totalLen -band 0xFF),           # Length, low byte
        0x00, 0x00,                             # SPID
        0x00,                                   # PacketID
        0x00                                    # Window
    )

    $packet = [System.Collections.Generic.List[byte]]::new()
    $packet.AddRange($header)
    $packet.AddRange($payload)

    return $packet.ToArray()
}

function Read-FullPreLoginResponse {
    <#
        Reads the server's complete Pre-Login response and returns its
        payload (the TDS header stripped).

        Reads the 8-byte header first to learn the declared total length,
        then loops until that many bytes have arrived, since a response may
        be split across several socket reads.
    #>
    param([System.IO.Stream]$Stream)

    $header = New-Object byte[] 8
    $readTotal = 0
    while ($readTotal -lt 8) {
        $n = $Stream.Read($header, $readTotal, 8 - $readTotal)
        if ($n -eq 0) { throw "Connection closed while reading Pre-Login response header." }
        $readTotal += $n
    }

    # The PRELOGIN response uses packet type 0x04 (TABULAR_RESULT), not 0x12.
    if ($header[0] -ne 0x04) {
        throw ("Unexpected TDS packet type in Pre-Login response: 0x{0:X2} (expected 0x04). The endpoint may not be SQL Server." -f $header[0])
    }

    $totalLen = ($header[2] -shl 8) -bor $header[3]
    $payloadLen = $totalLen - 8

    $payload = New-Object byte[] $payloadLen
    $readTotal = 0
    while ($readTotal -lt $payloadLen) {
        $n = $Stream.Read($payload, $readTotal, $payloadLen - $readTotal)
        if ($n -eq 0) { throw "Connection closed while reading Pre-Login response payload." }
        $readTotal += $n
    }

    return $payload
}

function Get-PreLoginEncryptionOption {
    <#
        Extracts the single ENCRYPTION byte (token 0x01) from a Pre-Login
        payload, or $null if the server did not report one.

        Walks the same options table the client builds: 5-byte entries of
        (Token, OffsetHi, OffsetLo, LengthHi, LengthLo) ending at a 0xFF
        token, with offsets relative to the start of the payload.
    #>
    param([byte[]]$Payload)

    $i = 0
    while ($i -lt $Payload.Length -and $Payload[$i] -ne 0xFF) {
        if ($Payload[$i] -eq 0x01) {
            $optOffset = ($Payload[$i + 1] -shl 8) -bor $Payload[$i + 2]
            $optLen    = ($Payload[$i + 3] -shl 8) -bor $Payload[$i + 4]
            # Bounds-check before indexing: the offset and length come
            # straight off the wire and are not trusted.
            if ($optLen -ge 1 -and ($optOffset + $optLen) -le $Payload.Length) {
                return $Payload[$optOffset]
            }
            return $null
        }
        $i += 5
    }
    return $null
}

function Get-EncryptionModeDescription {
    <#
        Renders the ENCRYPTION byte as readable text. See the ENCRYPTION
        MODES section in the script header for what each value implies.
    #>
    param($Value)

    switch ($Value) {
        0x00 { return "ENCRYPT_OFF (Force Encryption is OFF; full-stream TLS still requested by this client)" }
        0x01 { return "ENCRYPT_ON (server will encrypt because the client requested it)" }
        0x02 { return "ENCRYPT_NOT_SUP (server does NOT support TLS -- no certificate available this way)" }
        0x03 { return "ENCRYPT_REQ (Force Encryption is ON -- TLS required for the whole connection)" }
        default { return "unknown/unreported" }
    }
}

function Get-SqlServerCertOnce {
    <#
        Performs one complete retrieval attempt with a given set of TLS
        protocol versions, and returns the server's certificate as an
        X509Certificate2.

        Opens its own TCP connection rather than reusing one, because a
        failed TLS handshake leaves the socket in an indeterminate state
        (the peer may have sent an alert or torn the connection down). The
        Pre-Login exchange is cheap and plaintext, so repeating it per
        attempt costs little.

        Throws NotSupportedException when the server reports it cannot do
        TLS at all, which the caller uses to stop retrying. Any other
        failure is an ordinary exception and is worth retrying with
        different protocol versions.
    #>
    param(
        [string]$ServerName,
        [int]$Port,
        [System.Security.Authentication.SslProtocols]$SslProtocols,
        [int]$TimeoutMs = 15000
    )

    $tcp = New-Object System.Net.Sockets.TcpClient($ServerName, $Port)
    $stream = $tcp.GetStream()
    # Bound the plaintext Pre-Login reads. The handshake itself is bounded
    # separately, since its reads happen on other threads.
    $stream.ReadTimeout  = $TimeoutMs
    $stream.WriteTimeout = $TimeoutMs

    $tdsStream = $null
    $sslStream = $null

    try {
        # 1. Send Pre-Login. This packet is always plaintext, including when
        #    the server has Force Encryption enabled -- the upgrade happens
        #    after this exchange, never before it.
        $preLoginPacket = Build-PreLoginPacket
        $stream.Write($preLoginPacket, 0, $preLoginPacket.Length)
        $stream.Flush()

        # 2. Read the server's reply and find out which encryption mode applies.
        $responsePayload = Read-FullPreLoginResponse -Stream $stream
        $encByte = Get-PreLoginEncryptionOption -Payload $responsePayload
        Write-Host ("Pre-Login response received. Server encryption mode: {0}" -f (Get-EncryptionModeDescription $encByte))

        # A server that cannot encrypt has no certificate to present. This is
        # a capability statement, not a negotiation failure, so it is raised
        # as a distinct type the caller will not retry.
        if ($encByte -eq 0x02) {
            throw (New-Object System.NotSupportedException(
                "Server reported ENCRYPT_NOT_SUP -- it cannot negotiate TLS at all, so no certificate is available via this method."))
        }
        if ($encByte -eq 0x03) {
            Write-Host "Force Encryption is enabled on the server." -ForegroundColor Yellow
        }

        # 3. Upgrade to TLS. SslStream is layered over the TDS framing shim
        #    rather than the socket -- see TdsPreloginTlsStream above.
        [TdsCertCapture]::Reset()

        $tdsStream = New-Object TdsPreloginTlsStream($stream)
        $sslStream = New-Object System.Net.Security.SslStream(
            $tdsStream,
            $false,
            [TdsCertCapture]::Callback
        )

        Write-Host ("Performing TDS-encapsulated TLS handshake (protocols: {0}, timeout: {1}ms)..." -f $SslProtocols, $TimeoutMs)

        # Run the handshake as a task so it can be abandoned on a deadline.
        # The stream read timeouts set above do not reliably bound a stalled
        # handshake, because SslStream may be waiting on its own threads.
        $authTask = $sslStream.AuthenticateAsClientAsync($ServerName, $null, $SslProtocols, $false)
        if (-not $authTask.Wait($TimeoutMs)) {
            throw "TLS handshake timed out after ${TimeoutMs}ms with no usable response. Pre-Login succeeded, so the network path and the listener are working; suspect a TLS version or cipher mismatch, or a device between client and server interfering with the upgrade."
        }
        if ($authTask.IsFaulted) {
            # Unwrap so callers see the real failure, not an AggregateException.
            throw $authTask.Exception.InnerException
        }

        $tdsStream.CompleteHandshake()

        Write-Host ("TLS established: {0}, cipher {1}" -f $sslStream.SslProtocol, $sslStream.CipherAlgorithm) -ForegroundColor Green

        # RemoteCertificate is the authoritative source; the captured copy
        # covers the cases where it comes back empty.
        $raw = $sslStream.RemoteCertificate
        if (-not $raw) { $raw = [TdsCertCapture]::Captured }
        if (-not $raw) {
            throw "TLS handshake completed but no certificate was captured."
        }

        # Copy into an X509Certificate2 before the finally block disposes the
        # stream that owns the original.
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($raw)
    }
    finally {
        # Disposing SslStream disposes the shim and socket stream beneath it;
        # the elseif covers failing before SslStream was constructed.
        if ($sslStream) { $sslStream.Dispose() }
        elseif ($tdsStream) { $tdsStream.Dispose() }
        $stream.Dispose()
        $tcp.Close()
    }
}

Write-Host ("PowerShell {0} on {1}" -f $PSVersionTable.PSVersion, [System.Environment]::OSVersion.VersionString)
Write-Host "Connecting to $ServerName`:$Port ..."

# Protocol sets to try, in order, each on its own connection.
#
# TLS 1.2 leads because every supported SQL Server speaks it, and naming a
# version explicitly is the most portable option: SslProtocols::None, which
# defers the choice to the OS, is only honored on .NET Framework 4.7 and
# later. On 4.6.x it can fail outright with "must specify one protocol", so
# it is kept as a last resort rather than the default.
#
# The legacy set is second for instances on older Windows builds that have
# not enabled TLS 1.2.
$T = [System.Security.Authentication.SslProtocols]
$attempts = @(
    @{ Label = 'TLS 1.2';            Value = $T::Tls12 },
    @{ Label = 'TLS 1.0/1.1/1.2';    Value = ($T::Tls -bor $T::Tls11 -bor $T::Tls12) },
    @{ Label = 'OS default (None)';  Value = $T::None }
)

$cert2 = $null
$lastError = $null

foreach ($attempt in $attempts) {
    try {
        Write-Host ("`n--- Attempt: {0} ---" -f $attempt.Label) -ForegroundColor Cyan
        $cert2 = Get-SqlServerCertOnce -ServerName $ServerName -Port $Port `
            -SslProtocols $attempt.Value -TimeoutMs $TimeoutMs
        break
    }
    catch [System.NotSupportedException] {
        # The server told us it cannot encrypt. No protocol set changes that,
        # so stop rather than working through the remaining attempts.
        Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Not retrying other protocol versions: this is a server capability, not a version mismatch."
        return
    }
    catch {
        # Keep the last failure so it can be surfaced if nothing succeeds.
        $lastError = $_
        Write-Host ("Attempt '{0}' failed: {1}" -f $attempt.Label, $_.Exception.Message) -ForegroundColor Yellow
    }
}

if (-not $cert2) {
    Write-Host "`nAll attempts failed." -ForegroundColor Red
    throw $lastError
}

Write-Host "`n=== SQL Server TLS Certificate ===" -ForegroundColor Cyan

# Fields are printed individually rather than via Format-List, whose output
# for X509Certificate2 depends on the host's formatting data and can come
# back empty when the script runs non-interactively.
Write-Host ("Subject      : {0}" -f $cert2.Subject)
Write-Host ("Issuer       : {0}" -f $cert2.Issuer)
Write-Host ("NotBefore    : {0}" -f $cert2.NotBefore)
Write-Host ("NotAfter     : {0}" -f $cert2.NotAfter)
Write-Host ("Thumbprint   : {0}" -f $cert2.Thumbprint)
Write-Host ("SerialNumber : {0}" -f $cert2.SerialNumber)
Write-Host ("SigAlgorithm : {0}" -f $cert2.SignatureAlgorithm.FriendlyName)

# The SAN is what a modern client actually checks the hostname against, so
# it is worth showing. Matched by OID because the friendly name differs
# across platforms ("Subject Alternative Name" on Windows, "X509v3 Subject
# Alternative Name" where OpenSSL supplies the string).
$san = $cert2.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
if ($san) {
    Write-Host ("SubjectAltName: {0}" -f $san.Format($false))
} else {
    Write-Host "SubjectAltName: (none present)"
}

# Two conditions worth calling out, since both cause client connection
# failures once encryption is enforced and TrustServerCertificate is not set.
if ($cert2.Subject -eq $cert2.Issuer) {
    Write-Host "`nNote: Subject == Issuer -- self-signed certificate (SQL Server generates one automatically when no certificate is provisioned)." -ForegroundColor Yellow
}
if ($cert2.NotAfter -lt (Get-Date)) {
    Write-Host ("`nWARNING: certificate EXPIRED on {0}." -f $cert2.NotAfter) -ForegroundColor Red
}

# 'Cert' exports the DER-encoded public certificate only; no private key is
# involved, and none is available to a client in any case.
$bytes = $cert2.Export('Cert')
[System.IO.File]::WriteAllBytes($OutFile, $bytes)
Write-Host "`nCertificate exported to: $OutFile" -ForegroundColor Green
Write-Host "Inspect on Windows with:  certutil -dump `"$OutFile`""
