# Installs nk, the Nokku CLI, on Windows.
#
#   irm https://get.nokku.sh/nk.ps1 | iex
#
# Downloads the release binary from GitHub to %LOCALAPPDATA%\Programs\nk and
# puts that folder on the user PATH. No admin rights needed.
# Pin a version with $env:NK_VERSION = '1.2.3' before running it.

# The script block keeps the preferences below out of the calling session.
& {
    $ErrorActionPreference = 'Stop'
    # The progress bar makes downloads many times slower on Windows PowerShell 5.1.
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $releases = 'https://github.com/nokku-sh/nokku/releases'

    function Get-ReleaseFile($name) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $tmp $name)
        } catch {
            throw "could not download $name from $base ($($_.Exception.Message))"
        }
    }

    # A 32-bit shell on 64-bit Windows reports x86, the real one is in PROCESSOR_ARCHITEW6432.
    $arch = switch ("$env:PROCESSOR_ARCHITEW6432$env:PROCESSOR_ARCHITECTURE") {
        { $_ -match 'ARM64' } { 'arm64'; break }
        { $_ -match 'AMD64' } { 'amd64'; break }
        default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }

    $base = "$releases/latest/download"
    if ($env:NK_VERSION) { $base = "$releases/download/v$($env:NK_VERSION.TrimStart('v'))" }
    $binary = "nk_windows_$arch.exe"
    $sums = 'checksums.txt'

    $tmp = Join-Path ([IO.Path]::GetTempPath()) "nk-install-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading $binary..."
        Get-ReleaseFile $binary
        Get-ReleaseFile $sums

        # The release signs the checksum file. Without cosign only the download
        # is checked, not where it came from. Every Nokku release is signed by the
        # same shared workflow, so the repository is pinned as well.
        if (Get-Command cosign -ErrorAction SilentlyContinue) {
            Get-ReleaseFile "$sums.sigstore.json"
            & cosign verify-blob --bundle (Join-Path $tmp "$sums.sigstore.json") `
                --certificate-identity https://github.com/nokku-sh/.github/.github/workflows/go-release.yaml@refs/heads/main `
                --certificate-oidc-issuer https://token.actions.githubusercontent.com `
                --certificate-github-workflow-repository nokku-sh/nokku `
                (Join-Path $tmp $sums)
            if ($LASTEXITCODE -ne 0) { throw "the signature on $sums is not valid (cosign older than 3 cannot read it)" }
        } else {
            Write-Warning 'cosign is not installed, the release signature is not checked'
        }

        $want = foreach ($line in Get-Content (Join-Path $tmp $sums)) {
            $hash, $name = $line -split '\s+', 2
            if ($name -eq $binary) { $hash }
        }
        $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $binary)).Hash
        if (-not $want) { throw "$binary is not listed in $sums" }
        if ($want -ne $got) { throw "checksum mismatch for $binary" }

        $dir = Join-Path $env:LOCALAPPDATA 'Programs\nk'
        $target = Join-Path $dir 'nk.exe'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        # Windows cannot overwrite a running nk.exe, but it can rename it.
        Get-ChildItem -Path $dir -Filter 'nk.exe.old-*' | Remove-Item -Force -ErrorAction SilentlyContinue
        if (Test-Path $target) { Rename-Item -Path $target -NewName "nk.exe.old-$([guid]::NewGuid().ToString('N'))" }
        Copy-Item -Path (Join-Path $tmp $binary) -Destination $target
        Get-ChildItem -Path $dir -Filter 'nk.exe.old-*' | Remove-Item -Force -ErrorAction SilentlyContinue
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }

    $path = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($path -split ';') -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', "$path;$dir".TrimStart(';'), 'User')
        $env:Path = "$env:Path;$dir"
        Write-Host "Added $dir to your PATH. New terminals pick it up."
    }

    Write-Host 'nk is installed. Sign in with: nk login'
}
