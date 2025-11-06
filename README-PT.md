# Lean11 Image Optimizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows 11](https://img.shields.io/badge/Windows-11-0078D6.svg)](https://www.microsoft.com/windows/windows-11)
[![GitHub stars](https://img.shields.io/github/stars/carlosrabelo/lean11)](https://github.com/carlosrabelo/lean11/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/carlosrabelo/lean11)](https://github.com/carlosrabelo/lean11/issues)

**Otimizador Windows 11 de modo duplo: Crie ISOs otimizadas ou limpe sistemas instalados**

---

## Sobre

Lean11 é um otimizador Windows 11 baseado em PowerShell que opera em dois modos distintos:

**Modo Image**: Cria mídia de instalação Windows 11 otimizada
- Monta ISO original do Windows 11
- Remove bloatware antes da instalação
- Aplica otimizações de privacidade e performance
- Exporta ISO bootável otimizada (~36% menor)

**Modo Debloat**: Limpa sistemas Windows 11 já instalados
- Remove bloatware de sistemas em execução
- Aplica as mesmas otimizações do Modo Image
- Não requer ISO - executa diretamente na máquina
- Ideal para limpar instalações pré-instaladas ou existentes

Ambos os modos compartilham a mesma arquitetura modular usando hashtables para configuração e sistema de logging multinível.

### Filosofia de Design

O projeto adota os seguintes princípios:

- **Separação de Responsabilidades**: Cada função possui um objetivo único e bem definido
- **Configuração sobre Código**: Comportamento definido por estruturas de dados, não por lógica dispersa
- **Observabilidade**: Sistema de logging estruturado com níveis de severidade
- **Extensibilidade**: Adição de funcionalidades sem modificação de código-base
- **Resiliência**: Tratamento robusto de erros com blocos try-catch-finally

---

## Diferencial Técnico

### Arquitetura Baseada em Componentes

```
┌─────────────────────────────────────────┐
│     Configuração Declarativa            │
│  (Hashtables + Script Scope)            │
└──────────────┬──────────────────────────┘
               │
    ┌──────────▼──────────┐
    │  Core Functions     │
    │  - Validation       │
    │  - Transformation   │
    │  - Export           │
    └──────────┬──────────┘
               │
    ┌──────────▼──────────┐
    │  Orchestrator       │
    │  (Main Execution)   │
    └─────────────────────┘
```

### Sistema de Configuração

Todas as operações são definidas através de estruturas de dados:

```powershell
# Exemplo: Categorização de pacotes
$Script:PackageCategories = @{
    Gaming = @('Microsoft.XboxApp', 'Microsoft.XboxGameOverlay')
    Office = @('Microsoft.MicrosoftOfficeHub', 'Microsoft.Todos')
}

# Exemplo: Otimizações de registro
$Script:RegistryOptimizations = @{
    TelemetryDisable = @(
        @{Hive='zSYSTEM'; Path='...'; Name='...'; Type='REG_DWORD'; Value='0'}
    )
}
```

Esta abordagem permite modificações sem alteração de lógica.

---

## Instalação

### Requisitos de Sistema

| Componente | Especificação |
|-----------|---------------|
| Sistema Operacional | Windows 11 (host) |
| PowerShell | 5.1 ou superior |
| Privilégios | Administrador |
| Espaço em Disco | Mínimo 20GB livre |
| Mídia de Origem | ISO oficial Windows 11 |

### Preparação do Ambiente

**1. Obter ISO do Windows 11**

Fonte: https://www.microsoft.com/software-download/windows11

**2. Montar ISO no sistema**

Método: Windows Explorer → Botão direito → Montar

**3. Configurar política de execução (sessão temporária)**
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

**4. Executar otimizador**
```powershell
.\lean11.ps1 -ISO <letra> -SCRATCH <letra>
```

---

## Uso

### `lean11.ps1` (Script Unificado de Modo Duplo)

#### Modo Image (Otimização de ISO)

**Modo Padrão**
```powershell
# ISO montada em E:, área de trabalho em D:
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
```

**Modo com Preservação Seletiva**

Preservar Windows Terminal e Paint:
```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -KeepPackages "WindowsTerminal","Paint"
```

Preservar múltiplos pacotes:
```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -KeepPackages "Calculator","StickyNotes","ScreenSketch"
```

**Modo Simplificado**
```powershell
# Usa diretório do script como área de trabalho
.\lean11.ps1 -Mode Image -ISO E
```

#### Modo Debloat (Otimização de Sistema Live)

Execute em uma sessão do PowerShell com privilégios de administrador na máquina que será otimizada.

Debloat padrão:
```powershell
.\lean11.ps1 -Mode Debloat
```

Remover aplicativos padrão preservando Windows Terminal e Paint:
```powershell
.\lean11.ps1 -Mode Debloat -KeepPackages "WindowsTerminal","Paint"
```

Pular remoção do OneDrive:
```powershell
.\lean11.ps1 -Mode Debloat -SkipOneDrive
```

Pular otimizações de registro:
```powershell
.\lean11.ps1 -Mode Debloat -SkipRegistryOptimizations
```

Pular tarefas agendadas:
```powershell
.\lean11.ps1 -Mode Debloat -SkipScheduledTasks
```

**Nota**: Reinicie após a remoção caso elimine aplicativos provisionados ou o OneDrive.

---

## Execução Remota (IRM + IEX)

###    Aviso de Segurança + Limitações Técnicas

**NÃO RECOMENDADO** - Execução remota tem riscos de segurança E limitações técnicas:

**Riscos de Segurança:**
- Ataques man-in-the-middle
- Modificação de código sem detecção
- Sem verificação de integridade

**Limitações Técnicas:**
- Imports de módulos PowerShell falham remotamente
- Validação de parâmetros pode não funcionar corretamente
- Dependências de caminhos de arquivo quebram
- Problemas com processamento de metadados do script

### Métodos Remotos que Funcionam

**Método 1: Baixar depois Executar**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1" -OutFile "lean11.ps1"
```
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```
```powershell
.\lean11.ps1 -Mode Debloat
```

**Método 2: GitHub CLI (Recomendado)**
```powershell
gh repo clone carlosrabelo/lean11
```
```powershell
cd lean11
```
```powershell
.\lean11.ps1 -Mode Debloat
```

**Método 3: PowerShell Gallery (se disponível)**
```powershell
Install-Script -Name Lean11 -Force
```
```powershell
Lean11.ps1 -Mode Debloat
```

### Método IRM + IEX

```powershell
irm "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1" | iex
```

### Com Parâmetros

Modo Image com parâmetros (Método 1: Execução direta):
```powershell
Invoke-Expression "& { $(irm 'https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1') } -Mode Image -ISO E"
```

Modo Image com parâmetros (Método 2: Abordagem com variável):
```powershell
$script = irm "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1"
$script | Save-String lean11.ps1
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
```

Modo Debloat com parâmetros:
```powershell
Invoke-Expression "& { $(irm 'https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1') } -Mode Debloat -KeepPackages 'WindowsTerminal','Paint'"
```

### Alternativas Mais Seguras

**1. Download e Verificação**

Baixar primeiro:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1" -OutFile "lean11.ps1"
```

Verificar conteúdo (opcional):
```powershell
Get-Content lean11.ps1 | Select-Object -First 20
```

Executar após verificação:
```powershell
.\lean11.ps1 -Mode Debloat
```

**2. Verificação de Hash**
```powershell
# Baixar e verificar SHA256
$hash = Get-FileHash lean11.ps1 -Algorithm SHA256
# Substitua com hash real da página de releases do GitHub
$expectedHash = "HASH_SHA256_REAL_AQUI"  
if ($hash.Hash -eq $expectedHash) {
    .\lean11.ps1 -Mode Debloat
} else {
    Write-Error "Hash não corresponde! Script pode estar comprometido."
}
```

**3. GitHub CLI**
```powershell
gh repo clone carlosrabelo/lean11
```
```powershell
cd lean11
```
```powershell
.\lean11.ps1 -Mode Debloat
```

**Recomendação**: Sempre baixe e verifique scripts antes da execução, especialmente ao executar com privilégios de administrador.

---

## Operações Executadas

### Remoção de Componentes

O processo de otimização remove as seguintes categorias de software:

**Hardware/OEM**: Ferramentas específicas de fabricante
**Mídia**: Aplicativos de mídia não essenciais
**Produtividade**: Suite Office simplificada
**Comunicação**: Clientes de mensagem e email alternativos
**Entretenimento**: Jogos e Xbox services
**Utilidades**: Ferramentas redundantes do sistema

**Total**: 50+ pacotes AppX removidos

### Componentes Preservados

Os seguintes componentes essenciais do Windows permanecem **totalmente funcionais**:

- **Microsoft Store**: Instalação e atualização de aplicativos
- **Windows Defender**: Proteção de segurança e antivírus
- **Windows Update**: Atualizações e patches do sistema
- **Microsoft Edge**: Navegador padrão
- **Windows Copilot**: Assistente de IA (pode ser removido via KeepPackages se desejado)

### Otimizações de Sistema

**Bypass de Hardware**
- TPM 2.0 não obrigatório
- Secure Boot não obrigatório
- Requisitos de RAM/CPU relaxados
- Instalação em hardware legado habilitada

**Privacidade e Telemetria**
- Coleta de dados de diagnóstico: Desabilitada
- Advertising ID: Desabilitado
- Experiências personalizadas: Desabilitadas
- Serviços de telemetria: Parados

**Conteúdo Patrocinado**
- Apps OEM pré-instalados: Bloqueados
- Sugestões de conteúdo: Desabilitadas
- Instalações automáticas: Bloqueadas
- Content Delivery Manager: Neutralizado

**OOBE (Out of Box Experience)**
- Criação de conta local: Habilitada
- Requisitos de conta Microsoft: Removidos
- Configuração offline: Possível

---

## Arquitetura de Código

### Componentes Principais

| Função | Responsabilidade | Input | Output |
|--------|-----------------|-------|--------|
| `Initialize-Environment` | Setup de caminhos e logging | Parâmetros | Paths hashtable |
| `Get-SourceIso` | Validação de mídia fonte | Drive letter | Validated path |
| `Mount-WindowsInstallImage` | Montagem de WIM | Index | Image info |
| `Remove-BloatwarePackages` | Remoção categorizada | Categories | Removed count |
| `Apply-RegistryOptimizations` | Aplicação em lote | Optimization sets | Success status |
| `New-BootableIso` | Geração de mídia | Work dir | ISO path |

### Fluxo de Execução

```
[Inicialização] → [Validação] → [Montagem] → [Transformação] → [Otimização] → [Exportação] → [Limpeza]
       ↓              ↓             ↓              ↓                ↓              ↓            ↓
   Paths Setup   ISO Check   Mount WIM    Remove Apps     Registry Tweaks    Create ISO   Cleanup
```

### Sistema de Logging

Implementação de logging estruturado com níveis:

```powershell
Write-Log "Message" -Level Info      # Informational
Write-Log "Message" -Level Success   # Operation success (green)
Write-Log "Message" -Level Warning   # Non-critical issue (yellow)
Write-Log "Message" -Level Error     # Critical failure (red)
```

**Output**: `lean11_YYYYMMDD_HHmmss.log`

---

## Customização

### Adicionar Categoria de Remoção

Localizar `$Script:PackageCategories` no script:

```powershell
$Script:PackageCategories = @{
    # ... existentes ...

    CustomCategory = @(
        'Vendor.PackageName'
        'Another.Package'
    )
}
```

### Adicionar Otimização de Registro

Localizar `$Script:RegistryOptimizations`:

```powershell
$Script:RegistryOptimizations = @{
    # ... existentes ...

    CustomOptimizations = @(
        @{
            Hive  = 'zSOFTWARE'
            Path  = 'Path\To\Key'
            Name  = 'ValueName'
            Type  = 'REG_DWORD'
            Value = '1'
        }
    )
}
```

### Modificar Tarefas Agendadas

Localizar `$Script:ScheduledTasksToRemove`:

```powershell
$Script:ScheduledTasksToRemove = @(
    'Microsoft\Windows\Path\To\Task'
)
```

---

## Output e Artefatos

### Arquivos Gerados

**lean11.iso**
Imagem bootável otimizada (~3-4GB)
Compressão: Recovery (máxima)
Formato: ISO 9660 + UDF

**lean11_TIMESTAMP.log**
Log estruturado da execução
Formato: `[timestamp] [level] message`
Encoding: UTF-8

### Métricas de Otimização

| Métrica | Antes | Depois | Redução |
|---------|-------|--------|---------|
| Tamanho ISO | ~5.5GB | ~3.5GB | ~36% |
| Pacotes AppX | ~80 | ~30 | ~62% |
| Tarefas Agendadas | 150+ | 145 | ~3% |
| Tempo de instalação | ~25min | ~18min | ~28% |

---

## Performance

**Tempo de Processamento**: 35-90 minutos (varia com hardware)
**CPU Utilização**: Alta durante compressão WIM
**Disco I/O**: Intensivo durante cópia e exportação
**RAM Requerida**: Mínimo 4GB, recomendado 8GB+

---

## Troubleshooting

### Erro: "Execution policy is Restricted"

**Solução**:
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

### Erro: "Access Denied" durante operações

**Causa**: Privilégios insuficientes
**Solução**: Executar PowerShell como Administrador

### Erro: "Failed to mount image"

**Possíveis causas**:
- WIM corrompido
- Espaço em disco insuficiente
- Montagem anterior não desmontada

**Solução**:
```powershell
# Limpar montagens pendentes
Dism /Cleanup-Wim
```

### ISO não inicializa após criação

**Verificar**:
- Modo de boot UEFI vs Legacy
- Secure Boot desabilitado
- Mídia gravada corretamente

---

## FAQ Técnico

**Q: A imagem gerada é serviciável?**
A: Sim. Windows Update, instalação de drivers e pacotes de idioma funcionam normalmente.

**Q: Qual o método de compressão utilizado?**
A: Recovery compression (máxima compressão do DISM).

**Q: Funciona com ESD ao invés de WIM?**
A: Sim, o script detecta e converte automaticamente.

**Q: Posso usar em produção?**
A: Recomendado para uso pessoal e testes. Para produção, realizar testes extensivos.

**Q: Há bypass de ativação?**
A: Não. A ativação do Windows funciona normalmente.

---

## Limitações Conhecidas

- Não compatível com Windows 11 ARM (apenas x64/amd64)
- Requer ISO oficial da Microsoft (não funciona com builds modificadas)
- OneDrive removido permanentemente (não reinstalável via Store)
- Requer conexão internet para download de oscdimg.exe (se ADK não instalado)

---

## Roadmap

- [ ] Suporte para criação de perfis de configuração (.json)
- [ ] Modo interativo para seleção de pacotes
- [ ] Geração de relatório HTML pós-processamento
- [ ] Validação de integridade SHA256 da ISO gerada
- [ ] Suporte para múltiplas edições em lote

---

## Referências Técnicas

Este projeto foi desenvolvido utilizando a documentação oficial da Microsoft:

**DISM (Deployment Image Servicing and Management)**
[Microsoft Learn - DISM Technical Reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism---deployment-image-servicing-and-management-technical-reference-for-windows)

**Windows Assessment and Deployment Kit (ADK)**
[Microsoft - Download Windows ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install)

**Unattend Answer Files**
[Microsoft Learn - Answer Files Overview](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs)

**Windows Image Management**
[Microsoft Learn - Work with Windows Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/mount-and-modify-a-windows-image-using-dism)

**PowerShell DISM Module**
[Microsoft Learn - DISM PowerShell Reference](https://learn.microsoft.com/en-us/powershell/module/dism/)

---

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.

Projeto educacional open-source desenvolvido com base em documentação pública da Microsoft.

**Aviso Legal**: Este software é fornecido "como está", sem garantias de qualquer tipo.
O uso é por sua conta e risco. Não há suporte oficial.

---

**Lean11 Project** - Versão 1.1 - Novembro 2025
