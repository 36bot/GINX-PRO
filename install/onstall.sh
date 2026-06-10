#!/bin/sh
export GO_PKG=go1.19.1.linux-amd64.tar.gz
export DEBIAN_FRONTEND=noninteractive
set -e
bash ../install/ubuntu-update.sh &&
    cp -a ../install/.zshrc ../install/.p10k.zsh ../install/.antigen.zsh "$HOME"/ &&
    # packages will corrupt if you don't do a restart after ./ubuntu-update.sh
    apt install -y curl gnupg lsb-release libc6 runc ca-certificates git pigz xz-utils containerd certbot make g++ zsh zsh-antigen fontconfig wget build-essential&&
    [ -f '/usr/local/share/fonts/MesloLGS NF Regular.ttf' ] || wget -P /usr/local/share/fonts/ -i ../install/font.cfg && fc-cache -f -v &&
    [ -d ~/.oh-my-zsh ] ||  sh -c "../install/install.sh --keep-zshrc --unattended" &&
    chsh -s /usr/bin/zsh && zsh -c "source ~/.zshrc" &&
    [ -f /usr/local/go/bin ] || wget https://go.dev/dl/"$GO_PKG" && rm -rf /usr/local/go && tar -C /usr/local -xzf "$GO_PKG" &&  rm -rf "$GO_PKG" && export PATH="$PATH":/usr/local/go/bin &&
    echo "export PATH=$PATH:/usr/local/go/bin" | sudo tee -a /etc/profile &&
    echo "export PATH=$PATH:/usr/local/go/bin" | sudo tee -a ~/.zshrc && ln -sf /usr/local/go/bin/go /usr/bin/go &&
    go install golang.org/x/tools/...@latest && chmod +x ./start.sh && ./start.sh
