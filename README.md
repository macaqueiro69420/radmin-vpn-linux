# Radmin VPN para Linux

Execute o [Radmin VPN](https://www.radmin-vpn.com/) no Linux via Wine. Junte-se a redes VPN, veja pares, jogue jogos — tudo sem uma VM Windows.

> Eu não construí isso porque era mais fácil que uma VM. Eu construí porque achei que seria mais fácil que uma VM.

**Código assistido por IA.** Construído colaborativamente entre um humano e Claude (Anthropic). O driver, hooks e ponte foram escritos com extensa engenharia reversa assistida por IA do protocolo de driver não documentado do Radmin VPN usando Ghidra. **Isso funciona, mas não oferece garantias.** Não afiliado à Famatech. Radmin VPN é proprietário — baixe você mesmo em [radmin-vpn.com](https://www.radmin-vpn.com/). Use por sua conta e risco.

**Desenvolvido pela Confia Company.**

## Como funciona

O serviço Windows do Radmin VPN se comunica com um driver miniport NDIS para seu adaptador de rede virtual. O Wine não suporta NDIS, então substituímos o driver com nossa própria implementação que faz ponte para um dispositivo TAP Linux. Uma DLL hook lida com problemas de compatibilidade do Wine (nomeação de adaptador, permissões de registro). O resultado é um cliente Radmin VPN totalmente funcional rodando nativamente sob Wine.

```
Linux app ← TAP (radminvpn0) ← tap_bridge ← FIFO ← rvpnnetmp.sys (Wine driver) ← RvControlSvc.exe
```

## Pré-requisitos

- **Wine** >= 11.0 (testado no Wine 11.5 Arch Linux e no Wine 11.6 Ubuntu 24.04)
- **mingw-w64** compiladores cross-platform (`i686-w64-mingw32-gcc`, `x86_64-w64-mingw32-gcc`) — para compilar a partir do código fonte
- **python3** — para análise de logs do serviço
- **sudo** acesso — para criação de dispositivo TAP e roteamento
- **Suporte de kernel TUN/TAP** — geralmente embutido, verifique com `modprobe tun`
- **Instalador do Radmin VPN** — baixe de [radmin-vpn.com](https://www.radmin-vpn.com/)

### Arch Linux

```bash
sudo pacman -S wine mingw-w64-gcc python
```

### Ubuntu/Debian

```bash
sudo apt install wine64 wine32 gcc-mingw-w64 python3
```

## Início rápido

```bash
git clone https://github.com/baptisterajaut/radmin-vpn-linux.git
cd radmin-vpn-linux

# Opção A: baixar binários pré-compilados do GitHub Releases
mkdir -p build
TAG=$(curl -sI https://github.com/baptisterajaut/radmin-vpn-linux/releases/latest | grep -i location | grep -oP 'v[\d.]+')
curl -sL "https://github.com/baptisterajaut/radmin-vpn-linux/releases/download/${TAG}/radmin-vpn-linux-${TAG}.tar.gz" \
  | tar xz -C build/

# Opção B: compilar a partir do código fonte
make

# Baixe o instalador do Radmin VPN de https://www.radmin-vpn.com/
./run.sh --installer ~/Downloads/Radmin_VPN_*.exe
```

Nas execuções subsequentes, apenas:

```bash
./run.sh
```

## Compilando a partir do código fonte

Requer compiladores cross-platform `mingw-w64`. Binários pré-compilados estão disponíveis em [Releases](https://github.com/baptisterajaut/radmin-vpn-linux/releases) (construídos por CI em cada versão marcada) se você não quiser instalar mingw.

```bash
make          # compila tudo para build/
make clean    # remove artefatos de compilação
```

Produz:
- `build/rvpnnetmp.sys` — driver kernel Wine (PE 64-bit)
- `build/adapter_hook.dll` — Hook DLL (PE 32-bit)
- `build/rvpn_launcher.exe` — injetor de DLL (PE 32-bit)
- `build/netsh.exe` — substituto do netsh (PE 32-bit)
- `build/netsh64.exe` — substituto do netsh (PE 64-bit)
- `build/tap_bridge` — ponte TAP Linux nativa

## O que o `run.sh` faz

1. **Primeira execução**: instala o Radmin VPN via Wine (`/VERYSILENT`), remove o driver NDIS real (incompatível com Wine), registra nosso driver personalizado
2. **Cada execução**: cria um dispositivo TAP com suporte multicast, configura configurações sysctl do kernel (filtragem de caminho reverso, accept_local), inicia a ponte TAP-para-FIFO, configura o registro do Wine (GUID do adaptador, serviço de driver), inicia o serviço e GUI do Radmin VPN
3. **Ao sair** (Ctrl+C ou fechar GUI): mata o Wine, remove o dispositivo TAP, limpa

O wineprefix é armazenado em `./wineprefix/`. Um endereço MAC persistente é gerado na primeira execução e salvo no wineprefix.

## Arquitetura

| Componente | Descrição |
|---|---|
| `rvpnnetmp.sys` | Driver kernel Wine. Emula o miniport NDIS do Radmin. Manipula IOCTLs (VERSION, STATUS, SETUP, PEERMAC), codificação/decodificação de frames TLV, fila IRP para I/O sobreposto, roteamento de frames baseado em MAC para suporte multi-par. |
| `adapter_hook.dll` | DLL companheira carregada junto com RvControlSvc.exe. Hooks IAT: renomeia o adaptador TAP para corresponder ao nome esperado pelo Radmin, no-ops `RegSetKeySecurity` para contornar um bug do Wine SCM onde serviços não têm o SYSTEM SID. |
| `tap_bridge` | Binário Linux nativo. Retransmite frames ethernet entre o dispositivo TAP e pipes nomeados (FIFOs) que o driver Wine lê/escreve. |
| `netsh.exe` / `netsh64.exe` | Substitui o stub netsh do Wine (versões 32-bit e 64-bit). Traduz comandos Windows `netsh interface ip` para comandos Linux `ip addr`/`ip link` via um retransmissor baseado em arquivo. |
| `rvpn_launcher.exe` | Injeta `adapter_hook.dll` no processo do serviço Radmin via `CreateRemoteThread` + `LoadLibrary`. |

## Solução de problemas

**GUI presa em "Waiting for adapter"**: o driver não está carregando. Verifique se `wineprefix/drive_c/radmin_driver.log` existe e tem conteúdo. Se vazio, o registro do serviço de driver pode estar ausente — delete o wineprefix e execute novamente.

**Serviço morre imediatamente**: verifique `/tmp/radmin_service.log` para erros do Wine. Causa comum: wineprefix antigo de uma versão diferente do Wine. Delete `./wineprefix/` e execute novamente.

**0% perda de pacotes com um par, alta perda com muitos**: este foi o bug original — corrigido pelo roteamento de frames baseado em MAC no driver. Certifique-se de usar a compilação mais recente.

**Primeiro ping é lento (~1s)**: normal — é resolução ARP através do túnel VPN. Pings subsequentes são 40-80ms dependendo da distância do par.

## Limitações conhecidas

- Apenas uma instância pode executar por vez (FIFOs compartilhados em `/tmp/`)
- A rota on-link `26.0.0.0/8` afeta todo o sistema durante a execução (limpa ao sair)
- Versões mais antigas do Wine (< 11.0) podem ter comportamento de I/O sobreposto diferente que quebra o driver

## Suporte Minecraft LAN

O dispositivo TAP é configurado com suporte multicast para habilitar descoberta LAN do Minecraft. O script:
- Habilita multicast e allmulticast na interface TAP
- Entra no grupo multicast LAN do Minecraft `224.0.2.60`
- Configura configurações sysctl do kernel para permitir tráfego VPN (desabilita filtragem de caminho reverso, habilita accept_local)

## Notas

**Risco de ban.** Cada wineprefix fresco cria um novo ID de registro com os servidores da Famatech. Não delete e recrie seu wineprefix desnecessariamente. Reuse-o através de sessões.

**Contorno de bug do Wine.** O hook `RegSetKeySecurity` contorna uma [limitação conhecida do Wine](https://forum.winehq.org/viewtopic.php?t=37183) onde serviços não recebem o SYSTEM SID (S-1-5-18). Isso pode ser corrigido upstream em uma versão futura do Wine.

## Licença

**Licença Confia Company**

Este software é propriedade da Confia Company. O uso é estritamente limitado ao ConfiaOS 2.3, exceto para desenvolvedores autorizados pela Confia Company.

- Uso fora do ConfiaOS 2.3 é proibido, exceto para desenvolvedores com autorização explícita da Confia Company
- Modificação, redistribuição ou uso comercial sem permissão é estritamente proibido
- Todos os direitos reservados © Confia Company

Radmin VPN é software proprietário da Famatech Corp. Este projeto fornece apenas ferramentas de interoperabilidade — nenhum código da Famatech está incluído ou distribuído.
