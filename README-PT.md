# Lean11

Otimizador dual-mode em PowerShell para Windows 11: limpa uma instalação em uso ou gera uma ISO de instalação enxuta.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows 11](https://img.shields.io/badge/Windows-11-0078D6.svg)](https://www.microsoft.com/windows/windows-11)

## Destaques

- Modo Debloat limpa AppX, Copilot, Office Hub, Teams e tweaks de privacidade no PC em uso
- Modo Image gera `lean11.iso` a partir de uma ISO oficial do Windows 11 com tweaks DISM offline
- Mantém sempre Paint e Ferramenta de Captura; Terminal, Store, Edge e Sticky Notes ficam por omissão
- Debloat em one-liner via `irm`/`iex` (PowerShell elevado; revise a URL antes)
- Lista seletiva com `-KeepPackages` para preservar o que quiser
- Bypass de hardware e unattend OOBE só no modo Image (lab/hardware sem suporte — não é hardening)
- Transcript em `%TEMP%`; testes Pester dos helpers sem admin nem ISO

## Visão Geral

O Lean11 serve para uso pessoal ou de laboratório. **Debloat** remove AppX removíveis e aplica tweaks de registro/tarefas na instalação atual. **Image** reescreve a mídia com DISM e exporta uma ISO customizada. Prefira ISO oficial da Microsoft, execute sempre elevado e trate o resultado como imagem customizada — não como hardening de segurança.

| Modo | Quando usar | Precisa de ISO |
|------|-------------|----------------|
| `Debloat` | Limpar o PC que você está usando | Não |
| `Image` | Preparar mídia de instalação enxuta | Sim |

## Pré-requisitos

- **Host Windows 11** — necessário para executar o script
- **PowerShell 5.1+** — Windows PowerShell ou compatível
- **Privilégios de administrador** — elevação obrigatória (auto-eleva quando possível)
- **ISO oficial do Windows 11** — só no modo Image; [download na Microsoft](https://www.microsoft.com/software-download/windows11)
- **~20GB livres em disco** — scratch do modo Image (use `-SCRATCH` em um disco grande)
- **Windows ADK (opcional)** — fornece `oscdimg.exe`; senão o Lean11 pode baixá-lo e verificar Authenticode

## Instalação

### Clone (recomendado para o modo Image)

```powershell
gh repo clone carlosrabelo/lean11
cd lean11
Set-ExecutionPolicy Bypass -Scope Process
```

Mantenha `autounattend.xml` ao lado de `lean11.ps1` no modo Image.

### One-liner (só Debloat)

PowerShell elevado (revise a URL antes):

```powershell
iex "& { $(irm https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1) } -Mode Debloat"
```

Só `irm … | iex` não basta — passe `-Mode Debloat` (o padrão é `Image`).

## Início Rápido

Limpar a máquina atual (PowerShell elevado no repositório):

```powershell
.\lean11.ps1 -Mode Debloat
```

Pular remoção do OneDrive:

```powershell
.\lean11.ps1 -Mode Debloat -SkipOneDrive
```

Gerar ISO otimizada (unidade montada `E:`, scratch em `D:`):

```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
```

Reinicie após o Debloat se AppX ou OneDrive mudaram.

## Uso

Execute em uma sessão **elevada** do PowerShell.

### Modo Debloat

```powershell
.\lean11.ps1 -Mode Debloat
.\lean11.ps1 -Mode Debloat -SkipOneDrive
.\lean11.ps1 -Mode Debloat -KeepPackages "Xbox","Teams"
.\lean11.ps1 -Mode Debloat -SkipRegistryOptimizations -SkipScheduledTasks
```

Debloat remoto (mesmo one-liner da Instalação):

```powershell
iex "& { $(irm https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1) } -Mode Debloat -SkipOneDrive"
```

Listar AppX removíveis na máquina (útil antes/depois):

```powershell
Get-AppxPackage -AllUsers |
  Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } |
  Sort-Object Name |
  Select-Object -ExpandProperty Name
```

### Modo Image

```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
.\lean11.ps1 -Mode Image -ISO "C:\ISOs\Win11.iso" -SCRATCH D
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -KeepPackages "Xbox","Teams"
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -NonInteractive
```

Saída: `lean11.iso` ao lado do script, além do transcript em `%TEMP%`.

### O que é alterado

| Área | Comportamento |
|------|---------------|
| AppX | Gaming, Office Hub, Outlook, Teams, Copilot, Phone Link, Widgets, helpers OEM e mais, quando presentes |
| Mantidos por padrão | Store, Defender, Update, Edge, Terminal, Paint, Ferramenta de Captura, Sticky Notes, codecs, GPU/áudio OEM |
| Copilot | Remoção do app + `TurnOffWindowsCopilot`; M365 Copilot = Office Hub (também removido). Preserve com `-KeepPackages "Copilot","OfficeHub"` |
| Telemetria / ads | Tweaks de registro e tarefas nos dois modos |
| Bypass de hardware | Só Image (TPM / Secure Boot / RAM / CPU) |
| Unattend OOBE | Só Image — oculta conta online; sem admin com senha vazia |
| OneDrive | Debloat desinstala salvo `-SkipOneDrive`; Documents do usuário não são apagados |

### Limitações

- Apenas x64/amd64 (não ARM)
- ISO oficial da Microsoft obrigatória no modo Image
- OneDrive pode ser difícil de restaurar após a remoção
- Rede necessária se o ADK estiver ausente e for preciso baixar `oscdimg.exe`
- *Sugestões* do Menu Iniciar (anúncios LinkedIn/WhatsApp) não são AppX — limpeza de pin + política de consumer features ajudam; desafixe manualmente se restarem

## Configuração

Os padrões ficam em hashtables no topo de `lean11.ps1` (`PackageCategories`, `DefaultKeepPackages`, blocos de registro). Edite-as para mudar o que some ou permanece.

```powershell
$Script:DefaultKeepPackages = @(
    'Microsoft.Paint'
    'Microsoft.MSPaint'
    'Microsoft.ScreenSketch'
)

$Script:PackageCategories = @{
    Office = @(
        'Microsoft.MicrosoftOfficeHub'
        'Microsoft.OutlookForWindows'
    )
}
```

| Parâmetro | Modos | Função |
|-----------|-------|--------|
| `-Mode` | ambos | `Image` (padrão) ou `Debloat` |
| `-ISO` | Image | Letra (`E`) ou caminho para `.iso` |
| `-SCRATCH` | Image | Letra da unidade para work/mount |
| `-KeepPackages` | ambos | Padrões a preservar na remoção |
| `-SkipOneDrive` | Debloat | Pular desinstalação do OneDrive |
| `-SkipRegistryOptimizations` | Debloat | Pular tweaks de registro ao vivo |
| `-SkipScheduledTasks` | Debloat | Pular desabilitar tarefas de telemetria |
| `-ProductKey` | Image | Injetar no unattend gerado |
| `-NonInteractive` | ambos | Pular prompt interativo de saída |

## Estrutura do Projeto

```
lean11.ps1           # Otimizador dual-mode (ponto de entrada)
autounattend.xml     # Template OOBE de referência (sem senha admin vazia)
tests/               # Testes Pester dos helpers puros
README.md            # Documentação em inglês
README-PT.md         # Documentação em português
LICENSE              # MIT
```

## Desenvolvimento

Requer [Pester 5+](https://pester.dev/) no Windows:

```powershell
Install-Module Pester -Scope CurrentUser -Force
Invoke-Pester -Path .\tests
```

Os testes cobrem matching de pacotes, geração de unattend, helpers de registro e política de categorias. Não precisam de direitos de Administrador nem de ISO do Windows 11.

## Contribuição

1. Faça fork do repositório
2. Crie uma branch: `git checkout -b feat/description`
3. Mantenha `README.md` e `README-PT.md` sincronizados quando a documentação mudar
4. Rode `Invoke-Pester -Path .\tests` antes de abrir o PR
5. Abra um pull request com um resumo curto da mudança

## Licença

Este projeto está sob a licença MIT — veja [LICENSE](LICENSE) para detalhes.

Use por sua conta e risco. O Lean11 é um projeto educacional não oficial baseado na documentação pública DISM/ADK da Microsoft; não é afiliado à Microsoft.
