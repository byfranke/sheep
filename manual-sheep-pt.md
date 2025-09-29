# **Manual do Sheep Bot**

## Introdução

Bem-vindo ao manual do **Sheep Bot**! Este bot Discord é uma ferramenta de cibersegurança, projetado especificamente para profissionais de **threat intelligence**, **threat hunting** e **security operations**. 

O Sheep Bot oferece um conjunto abrangente de ferramentas que automatizam tarefas de segurança diretamente no Discord, eliminando a necessidade de alternar entre múltiplas plataformas e interfaces web.

### Primeiros Passos

Para começar a usar o bot, utilize estes comandos essenciais:
- **`/about`** - Visualiza informações sobre a versão atual e novidades
- **`/help`** - Exibe a lista completa de comandos disponíveis
- **`/version`** - Mostra detalhes da versão e changelog

## Ferramentas de Security Analysis

### Comando `/vt` - VirusTotal Integration

O comando **`/vt`** é uma das principais ferramentas do Sheep Bot, proporcionando acesso direto ao **VirusTotal** sem sair do Discord. O VirusTotal utiliza mais de 70 engines de antivírus para análise multi-engine de arquivos, URLs, domínios e endereços IP.

#### Funcionalidades Suportadas:

**URLs e Domínios:**

`/vt https://example.com   
/vt malicious-domain.com.  `

**Hashes de Arquivos (MD5, SHA1, SHA256):**

`/vt 13400d5c844b7ab9aacc81822b1e7f02    
/vt a1b2c3d4e5f6789012345678901234567890abcd   `

**Endereços IP:**

`/vt 49.89.34.10  `

#### Interpretando os Resultados

O Sheep Bot apresenta os resultados de forma estruturada:

- **Threat Level**: Classificação geral (CLEAN, SUSPICIOUS, MALICIOUS DETECTED)
- **Detection Rate**: Proporção de engines que detectaram ameaças (ex: 19/98 = 19.4%)
- **Engine Detections**: Lista detalhada dos antivírus que identificaram ameaças
- **Metadata**: Informações adicionais como tipo de arquivo, tamanho, timestamps

#### Exemplo de uso com URL:
Para verificar uma URL suspeita, como a https://salat.cn que foi reportada no canal **#ioc-feed** do nosso threat feed, basta digitar:

`/vt https://salat.cn  `

### Verificando um Arquivo com o Comando /vt

Além de URLs, você também pode verificar a segurança de um arquivo. O **VirusTotal** usa uma identificação única chamada "hash" para analisar e comparar arquivos.

#### Extração de Hashes para Análise

**Windows (PowerShell):**
```powershell
# SHA256 (recomendado)
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA256

# MD5
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm MD5

# SHA1
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA1
```

**Linux/macOS (Terminal):**
```bash
# SHA256
sha256sum /path/to/file

# MD5
md5sum /path/to/file

# SHA1
sha1sum /path/to/file
```

#### Exemplo de uso com Hash:
No nosso exemplo, vamos utilizar a hash MD5 de um arquivo reportado no **#ioc-feed**. Basta usar o comando /vt e a hash que você copiou:

`/vt 13400d5c844b7ab9aacc81822b1e7f02   `

### Verificando um Endereço IP com o Comando /vt

Você também pode usar o comando **/vt** para verificar a reputação de um IP suspeito.

#### Exemplo de uso com IP:
Para verificar o IP `49.89.34.10` que foi reportado no **#ioc-feed**, basta digitar:

`/vt 49.89.34.10   `

## Análise de Reputação de IP com /ipcheck

O comando **/ipcheck** utiliza o **AbuseIPDB**, uma base de dados colaborativa que coleta relatórios de IPs suspeitos e maliciosos de administradores de sistema e pesquisadores de segurança ao redor do mundo. É uma excelente ferramenta para verificar se um endereço IP já foi reportado por atividades maliciosas como spam, ataques de força bruta, scanning de portas, botnet, entre outros.

**Como usar o comando /ipcheck:**
O que ele faz? Consulta a reputação de um IP na base de dados do AbuseIPDB, mostrando o histórico de atividades maliciosas.

**Exemplo de uso:**
Para verificar um IP suspeito encontrado nos logs do servidor ou reportado no **#ioc-feed**:

`/ipcheck 49.89.34.10   `

O Sheep Bot retornará informações detalhadas como:
- **Confidence Score**: Percentual de confiança sobre a maliciosidade do IP
- **Abuse Reports**: Número de relatórios de abuso
- **Last Reported**: Data do último relatório
- **Country**: País de origem do IP
- **ISP**: Provedor de internet
- **Usage Type**: Tipo de uso (datacenter, residential, etc.)

## Reconnaissance com Shodan

O **Shodan** é conhecido como o "motor de busca para dispositivos conectados à internet". Diferente de motores de busca tradicionais que indexam websites, o Shodan mapeia dispositivos e serviços que estão expostos na internet, incluindo câmeras, roteadores, servidores, sistemas industriais e muito mais.

**Tipos de pesquisa que podem ser feitas pelo Shodan:**

**Por Porta:**
- Buscar todos os dispositivos com uma porta específica aberta
- Exemplo: `port:22` (SSH), `port:80` (HTTP), `port:443` (HTTPS)

**Por Cidade:**
- Localizar dispositivos em uma cidade específica
- Exemplo: `city:"São Paulo"`, `city:"New York"`

**Por Empresa/Organização:**
- Encontrar dispositivos de uma organização específica
- Exemplo: `org:"Google"`, `org:"Amazon"`

**Por Endereço IP:**
- Verificar informações detalhadas de um IP específico
- Histórico de serviços, portas abertas, vulnerabilidades

**Por Produto/Serviço:**
- Localizar dispositivos executando software específico
- Exemplo: `product:"Apache"`, `product:"nginx"`

### Diferença: Shodan vs /portscan

É importante entender a diferença fundamental entre consultas no **Shodan** e o comando **/portscan**:

**Shodan (Base de Dados):**
- Utiliza dados **previamente coletados** através de scanning contínuo da internet
- Os resultados mostram o estado **histórico** dos dispositivos
- Pode conter informações desatualizadas (dias, semanas ou meses)
- Vantagem: Rápido e não gera tráfego direto para o alvo
- Limitação: Informações podem estar desatualizadas

**Comando /portscan (Tempo Real):**
- Executa varredura **em tempo real** no momento da consulta
- Mostra o estado **atual** das portas do alvo
- Informações sempre atualizadas
- Vantagem: Dados precisos e atuais
- Limitação: Gera tráfego direto para o alvo e pode ser detectado

**Quando usar cada um:**

**Use Shodan quando:**
- Quiser fazer reconnaissance inicial sem ser detectado
- Precisar de informações históricas sobre um alvo
- Quiser mapear a infraestrutura de uma organização
- Estiver fazendo threat intelligence passiva

**Use /portscan quando:**
- Precisar confirmar o estado atual de um serviço
- Estiver em fase de verificação ativa
- Quiser validar se uma vulnerabilidade ainda existe
- Estiver fazendo teste de penetração autorizado

**Exemplo de uso:**

## Assistente para Consultas de Cybersecurity

O Sheep Bot inclui um **chatbot básico** que pode ajudar com perguntas simples sobre cybersecurity e algumas tarefas relacionadas. É útil para consultas rápidas quando você precisa de informações básicas ou quer uma segunda opinião sobre IOCs.

**O que o assistente pode fazer:**
- Responder perguntas básicas sobre malware, phishing, IOCs, APTs
- Dar uma análise simples de indicators suspeitos
- Explicar conceitos básicos de cybersecurity
- Auxiliar com tarefas simples de threat intelligence

**Como usar o comando /ask:**

**Para análises básicas de IOCs reportados no #ioc-feed:**

**Análise de IP:**
```
/ask analise este IP 49.89.34.10
```

**Análise de Hash:**
```
/ask analise esta hash 13400d5c844b7ab9aacc81822b1e7f02
```

**Análise de URL:**
```
/ask analise esta URL https://salat.cn
```

**Para perguntas gerais:**
```
/ask what is APT29?
/ask como identificar ataques de phishing?
```

O assistente oferece uma análise básica que pode complementar os resultados técnicos do VirusTotal e outras ferramentas especializadas.

## Professional Security Operations

### Workflows Automatizados

O Sheep Bot oferece **workflows profissionais** para:

 `/workflow incident_response`
- Geração automatizada de planos de resposta a incidentes
- Templates para Malware, Breach, Phishing
- Gerenciamento de severidade e escalação
- Integração com metodologias NIST/SANS

 `/workflow threat_intel`
- Análise avançada de threat intelligence
- Enriquecimento multi-source de IOCs
- Scoring de risco e recomendações
- Suporte a IPs, domínios, hashes, URLs

 `/workflow vulnerability_assessment`
- Avaliação de vulnerabilidades
- Metodologia step-by-step
- Tracking de progresso
- Compliance com frameworks NIST/SANS

### Incident Response Automatizado

 `/incident_response` - Geração de Planos IR
Cria planos profissionais de resposta a incidentes baseados no tipo e severidade da ameaça.

**Tipos suportados:**
- **Malware**: Análise e contenção de software malicioso
- **Breach**: Resposta a violações de dados
- **Phishing**: Tratamento de campanhas de phishing
- **APT**: Resposta a Advanced Persistent Threats

## Threat Intelligence

### Feeds Automatizados

O bot monitora automaticamente **18+ fontes de security intelligence**, fornecendo:

`/rss_status` - Status dos Feeds RSS
Verifica o status e canais dos feeds de threat intelligence.

`/ioc_status` - Status dos IOCs
Monitora o status dos feeds de Indicators of Compromise.

### Fontes de Intelligence Monitoradas:
- Feeds de IOCs em tempo real
- Relatórios de threat actors
- Vulnerabilidades zero-day
- Campanhas de malware ativas
- Threat landscape updates

#rss-feed #ioc-feed

## Black Sheep Membership

### Benefícios Premium

Os **membros Black Sheep** têm acesso a funcionalidades avançadas:

#### Ferramentas Exclusivas:
- **Scanning completo**: Acesso total às ferramentas de portscan
- **Usage ilimitado**: Sem limitações mensais
- **Priority support**: Suporte prioritário
- **Advanced workflows**: Workflows profissionais completos

#### Como Verificar Membership:

`/membership - Verifica status de membership  
/redeem <code> - Resgata código de membership `

### Limites para Usuários Gratuitos:
- **Security commands**: Uso limitado mensal
- **Port scanning**: Acesso restrito
- **Workflows**: Versões básicas

## Integração com CTI Workflows

### Exemplo de Workflow Completo

Para analistas de **Cyber Threat Intelligence**, um workflow típico seria:

1. **Identificação de IOC suspeito**
   ```
   /vt <hash_or_url_or_ip>
   ```

2. **Análise contextual com assistente**
   ```
   /ask analyze this IOC: <details>
   ```

3. **Geração de workflow de threat intel**
   ```
   /workflow threat_intel
   ```

4. **Documentação para incident response**
   ```
   /incident_response <type> <severity>
   ```

### Integração com Threat Hunting

Para **threat hunters**, o bot oferece:
- Análise rápida de artefatos suspeitos
- Correlação automática de IOCs
- Enriquecimento de contexto via assistente
- Workflows de investigação estruturados

# Boas Práticas de Uso

### Segurança Operacional

1. **Verificação de IOCs**: Sempre valide IOCs suspeitos antes de proceder com análises mais profundas
2. **Documentação**: Use os workflows para manter documentação consistente
3. **Escalação**: Siga os procedimentos de escalação sugeridos pelos workflows
4. **Correlação**: Combine múltiplas ferramentas para análise completa

### Eficiência no Discord

1. **Canais dedicados**: Use canais específicos para análises de segurança
2. **Histórico**: Mantenha histórico de análises para referência futura
3. **Colaboração**: Compartilhe resultados com a equipe de forma estruturada


## Troubleshooting e Suporte

### Problemas Comuns

**Limite de rate limiting atingido:**
- Aguarde o reset do limite ou considere upgrade para Black Sheep

**Erro na análise:**
- Verifique se o formato do input está correto (URL, hash, IP)
- Confirme se o recurso está disponível no VirusTotal

**Comandos não funcionando:**
- Verifique permissões do bot no canal
- Confirme se o comando foi digitado corretamente

### Contato e Suporte

- **Developer**: byFranke
- **Website**: https://sheep.byfranke.com/
- **Discord**: Utilize o sistema de tickets no servidor
- **Documentação**: Comando `/help` para referência rápida


## Licenciamento

**Licença**: Proprietária (Authorized use only)
**Uso responsável**: Use o bot de forma ética e conforme os [termos de serviço](https://byfranke.com/pages/sheep-terms.html)
**Targets autorizados**: Apenas para análise de ameaças legítimas


*Este manual cobre as principais funcionalidades do Sheep Bot. Para atualizações e novos recursos, consulte regularmente o comando `/about`.*
