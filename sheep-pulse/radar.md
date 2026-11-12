# Radar no Pulse: monitoramento de exposição do domínio

O Radar dá uma nota de A a F para o que um domínio já expõe na internet, só com dados públicos: e-mail (SPF, DKIM e DMARC), site e certificados, subdomínios esquecidos, portas expostas, reputação e domínios parecidos. Na aba Radar do Pulse, a Sheep monitora os domínios da sua empresa: analisa cada um de novo a cada 24 horas e manda um e-mail quando a nota piora ou surge um ponto de atenção grave.

O Radar é passivo. Ele não faz varredura de portas, não tenta acessar nenhum sistema e não envia nada ao domínio além de uma visita comum ao site, como um navegador.

## Pré-requisitos

* Plano pago ativo. Domínios por plano: Sheep Plus e Black Sheep, 1; Sheep Pro, 5; Sheep Pro Max, 20. O período de avaliação não inclui o monitoramento.
* Acesso à Sheep Platform em `https://sheep.byfranke.com/app`.

## Comprovar que o domínio é seu

A Sheep só monitora um domínio quando a conta comprova o controle de um e-mail nesse domínio. Domínios de e-mail gratuito (gmail.com, outlook.com e parecidos) não podem ser monitorados.

* **O domínio é o do e-mail da sua conta.** Quem entra com `service@empresa.com.br` monitora `empresa.com.br` na hora. Um e-mail num subdomínio (`ti@mail.empresa.com.br`) também vale.
* **Outro domínio.** Informe o e-mail de quem responde por ele, no próprio domínio (por exemplo, `ti@cliente.com.br`). A Sheep envia a essa pessoa um pedido que mostra o e-mail da sua conta. O monitoramento começa quando ela abre o link e clica em "Autorizar o monitoramento". O link vale por 72 horas e a autorização dura 12 meses; depois disso, é preciso pedir de novo.

## Como monitorar

1. Acesse `https://sheep.byfranke.com/app` e abra o Pulse.
2. Clique na aba Radar.
3. Em "Monitorar um domínio", digite o domínio.
4. Em "O que acompanhar", marque as áreas que devem gerar aviso e escolha quando avisar.
5. Se o domínio for o do e-mail da sua conta, clique em "Começar a monitorar". Se não for, informe o e-mail de quem responde por ele e clique em "Enviar pedido de autorização".

A primeira análise leva até dois minutos.

## Áreas analisadas

Toda análise cobre as seis áreas. As que você marcar geram aviso; dá para mudar depois em "Preferências", no cartão do domínio.

* E-mail: SPF, DKIM, DMARC e MTA-STS, ou seja, se dá para enviar e-mail falso em nome da empresa.
* Superfície exposta: subdomínios esquecidos no ar e serviços sensíveis abertos para a internet.
* Site e TLS: HTTPS, HSTS, cabeçalhos de segurança e versões antigas de TLS.
* Reputação: domínio e servidores em listas de phishing, malware e ameaças.
* Marca: domínios parecidos registrados por terceiros, base de golpes.
* Domínio: registro, DNSSEC e quem pode emitir certificados (CAA).

## O que a aba mostra

* A nota de cada domínio, a nota anterior quando ela mudou, a pontuação de 0 a 100 e a data da última análise.
* O relatório completo: a nota de cada área, cada ponto de atenção com a gravidade, a explicação e as evidências, e o que está certo.
* "Analisar agora", para uma nova análise depois de uma correção, no máximo uma vez por hora por domínio.

O relatório mostra os pontos fracos do domínio. Não o encaminhe a quem não precisa.

## Avisos por e-mail

Dois tipos de e-mail, ambos para o e-mail da sua conta:

* **Aviso imediato**, na análise diária em que a nota geral cai (por exemplo, de A para C) ou em que aparece, numa área marcada, um ponto de atenção alto ou crítico que não estava na análise anterior. Os dois podem ser desligados em "Preferências". A primeira análise de um domínio não gera aviso.
* **Lembrete dos pontos em aberto**, um resumo do que continua exposto, na frequência que você escolher por domínio: a cada 7, 15, 30 ou 90 dias, ou desligado. O padrão é 30 dias. O lembrete só é enviado enquanto houver pontos de atenção em aberto.

## Limites

* Uma análise automática por domínio a cada 24 horas (a frequência da análise é fixa; a do lembrete é sua).
* Nos planos Sheep Plus e Black Sheep, o cartão "Mais domínios no Sheep Pro" mostra o que o plano seguinte libera; no Sheep Pro, o do Sheep Pro Max.
* Uma análise manual por domínio por hora.
* Três pedidos de autorização por conta por dia, e dois por endereço de e-mail por dia.

Se o plano mudar para um com menos domínios, os domínios cadastrados por último ficam pausados até você remover algum ou voltar ao plano anterior. Um domínio pausado não é analisado e não mostra o relatório.

## Parar de monitorar

Na aba Radar, clique em "Remover" ao lado do domínio. Os avisos param na hora.

## Solução de problemas

`Domínios de e-mail gratuito não podem ser monitorados`
: O domínio é de um provedor de e-mail aberto ao público. Esses domínios não pertencem a uma empresa cliente.

`O e-mail precisa ser do próprio domínio`
: O pedido de autorização só pode ir para um endereço no domínio que você quer monitorar.

`A pessoa não recebeu o pedido`
: Peça para conferir a caixa de spam. Um novo pedido para o mesmo domínio invalida o anterior.

`Autorização expirada: peça de novo`
: Passaram-se 12 meses desde a autorização. Cadastre o domínio de novo para enviar outro pedido.

## Suporte

Dúvidas técnicas: `https://sheep.byfranke.com/discord`.

Assuntos comerciais: `https://byfranke.com/#Contact`.
