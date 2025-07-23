Write-Host "Starting PassAuth Stream Cipher - Simple Version"
Write-Host "=============================================="

# Compile
Write-Host "Compiling..."
javac PassAuthSimple.java

if ($LASTEXITCODE -eq 0) {
    Write-Host "Compilation successful!"
    Write-Host "Starting GUI application..."
    java PassAuthSimple
} else {
    Write-Host "Compilation failed!"
    exit 1
}
