#!/bin/bash
echo "Checking VAPT Tools Installation..."

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "✅ $1 is installed: $(command -v $1)"
        $1 --version 2>&1 | head -n 1
    else
        echo "❌ $1 is NOT installed"
    fi
}

check_tool nmap
check_tool nikto
check_tool sqlmap
check_tool hydra
check_tool nuclei
check_tool amass
check_tool sublist3r
check_tool testssl.sh
check_tool dig
check_tool whois

echo "Check complete."
