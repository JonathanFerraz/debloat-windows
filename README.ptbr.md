# ⚡ Ferramenta de Otimização e Debloat para Windows (Foco em Jogos)

<img src="./.github/images/windows.svg" alt="Windows Logo" width="96" />

Um script em PowerShell poderoso e personalizável, desenvolvido para **remover bloatware**, **otimizar** e **ajustar o Windows** para obter **máximo desempenho**, menor latência e uma **experiência de jogo aprimorada**.

> Atualmente em desenvolvimento.

![Status](https://badgen.net/badge/Status/Estável/red?icon=dockbit)
![Plataforma](https://badgen.net/badge/Plataforma/Windows/red?icon=windows)
![SOCD](https://badgen.net/badge/SOCD/2.0/red?icon=terminal)
[![Licença: MIT](https://badgen.net/github/license/JonathanFerraz/debloat-windows?color=red&icon=github)](LICENSE)

<p align="right"><a href="README.md">Mudar para Inglês (EN)</a></p>

---

## 🚀 Principais Funcionalidades

- **Limpeza do Sistema**
  - Remove arquivos temporários
  - Executa limpeza de disco usando ferramentas nativas

- **Remoção de Aplicativos**
  - Desinstala apps internos desnecessários
  - Remove OneDrive, Edge e outros bloatwares pré-instalados
  - Modo opcional para debloat de login Xbox (escolha entre manter ou desativar compatibilidade de login)

- **Otimização de Rede**
  - Ajusta a pilha TCP/IP para menor latência
  - Define servidores DNS rápidos e confiáveis

- **Ajustes de Desempenho**
  - Ativa o plano de energia **Desempenho Máximo**
  - Desativa hibernação e tarefas agendadas desnecessárias
  - Desativa efeitos visuais para maior responsividade

- **Ajustes no Sistema**
  - Aplica otimizações no registro e serviços
  - Desativa telemetria, coleta de dados e serviços em segundo plano desnecessários

- **Desativação de Recursos**
  - Desativa recursos legados e não utilizados: Internet Explorer, Hyper-V, Media Player, etc.

- **Melhorias na Latência de Entrada**
  - Ativa SOCD (Simultaneous Opposite Cardinal Direction)
  - Desativa componentes do sistema com alta latência

- **Ponto de Restauração**
  - Cria automaticamente um ponto de restauração antes de aplicar mudanças

---

## 🧠 Ajustes Recomendados no Gerenciador de Dispositivos

Para reduzir ainda mais a latência e melhorar o desempenho em jogos, desative os seguintes dispositivos pelo **Gerenciador de Dispositivos**:

- AMD Controller Emulation
- AMD Crash Defender
- Composite Bus Enumerator
- High Precision Event Timer (HPET)
- Microsoft Hyper-V Virtualization Infrastructure Driver
- Microsoft Virtual Drive Enumerator
- NDIS Virtual Network Adapter Enumerator
- Remote Desktop Device Redirector Bus
- System Speaker

---

## 🛠️ Como Usar

1. **Download**  
   Clone ou baixe este repositório para seu computador.

2. **Execute como Administrador**  
   Clique com o botão direito no arquivo `debloat.ps1` e selecione **"Executar como administrador"**.

3. **Escolha o Modo de Login Xbox**

- O script pergunta se você deseja desabilitar recursos relacionados ao login do Xbox.
- Se escolher **Sim**, componentes de login Xbox/Microsoft podem ser removidos/desativados.
- Se escolher **Não**, a compatibilidade com login Xbox é preservada.

4. **Opcional (modo por parâmetro)**

- Execute com `-DisableXboxLoginFeatures` para forçar o debloat de login Xbox sem prompt.

5. **Opcional (scripts pós-debloat para alternar Xbox/Store)**

- Reativar compatibilidade Microsoft Store / Xbox: [scripts/fixes/restore-xbox-store.ps1](scripts/fixes/restore-xbox-store.ps1) — re-aplica serviços e ajustes de registro e tenta re-registrar pacotes da Store/Xbox.
- Reparar login Xbox (alternativa): [scripts/fixes/repair-xbox-login.ps1](scripts/fixes/repair-xbox-login.ps1) — limpa o arquivo hosts e corrige serviços/registro relacionados ao login Xbox.
- Desativar compatibilidade Microsoft Store / Xbox: [scripts/fixes/disable-xbox-store-features.ps1](scripts/fixes/disable-xbox-store-features.ps1) — define AppPrivacy para negar acesso, adiciona bloqueio em `login.live.com` no hosts e desabilita serviços Xbox.
- Remover pacotes do Xbox (opcional): execute `scripts\bloatware\remove-apps.ps1 -RemoveXboxComponents` para remover pacotes Appx relacionados ao Xbox.

6. **Opcional (scripts de debloat pós-instalação por GPU)**

- AMD: `scripts\\bloatware\\radeon-software-post-install-debloat.ps1`
- NVIDIA: `scripts\\bloatware\\nvidia-software-post-install-debloat.ps1`

7. **Reinicie o Sistema**  
   Reinicie o Windows para aplicar completamente as alterações.

---

## ✅ Boas Práticas

- ⚠️ **Faça backup do sistema** antes de executar qualquer script de nível sistêmico.
- 🎮 Verifique e instale os drivers mais recentes de GPU, chipset e rede após a otimização.
- 🧩 Personalize os scripts como `registry.ps1` ou `services.ps1` conforme suas necessidades.

---

## 📌 Observações

- Alguns recursos e apps serão **removidos ou desativados permanentemente**.
- Este script é focado em **performance**: ideal para **PCs gamers**, configurações de baixa latência e usuários avançados.
- Use com responsabilidade e revise cada seção se tiver dúvidas.

---

## 📄 Licença

Este projeto é open-source e está licenciado sob os termos da [Licença MIT](LICENSE).  
**Use por sua conta e risco.**

---

💬 Encontrou um bug ou tem sugestões? [Abra uma issue](https://github.com/JonathanFerraz/debloat-windows/issues)

---

<p align="center">© 2025 R Y Z Ξ N Optimizer.</p>
