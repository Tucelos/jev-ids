# Arquitetura da Arena: o que cada peça faz e por que é assim

Guia de estudo. Cada seção descreve um módulo respondendo duas perguntas: **que problema ele
resolve** e **o que quebraria sem ele**. As decisões que um examinador vai perguntar estão marcadas
com ▸ e têm resposta completa no lugar.

O protocolo — a especificação que este código implementa — é
[`loop-design.md`](loop-design.md). Onde os dois puderem divergir, o comentário no código diz por
onde ler. O vocabulário é o de [`CONTEXT.md`](../../CONTEXT.md): Flow, Category, Split, Detector,
Prediction, Verdict. Os substantivos da Arena — Context, playbook, Rule, Round, Strategy, donor,
gate, Feedback — ficam em inglês porque é assim que estão no código e nos registros.

---

## O laço em uma frase

Um **atacante** muta Flows de ataque até o Detector parar de alertar; o tráfego resultante é julgado
sob o **Context** em vigor; um **analista** simulado rotula a fração que teria tempo de rotular; um
**curador** lê só esses rótulos e propõe Contexts novos; um **gate** aceita ou recusa cada proposta
medindo-a num Split retido. Isso é uma Round. Dez Rounds são uma Run.

```
                 ┌─────────── Strategy (bucket + levers) ────────────┐
                 │                                                    ▼
  attacker ──probe──► Detector(Context) ──► traffic ──► analyst ──► curator ──► gate ──► Context'
   (donors)            ▲                    (arena)    (budget)    (LLM ou       (arena-val,
                       └──────────── Context em vigor ──────────────  heurístico)  pareado)
```

---

## `context.py` — o Context

**Problema.** Precisa existir uma fronteira exata entre *o que o curador pode mudar* e *o que é
protocolo*. Sem ela, um curador que reescrevesse as instruções ou o texto das perguntas estaria
mudando o experimento e não a defesa.

**O que é.** Um `Context` é uma versão do que o curador pode mudar, e só isso: um **playbook** (até
15 `Rule`s, uma frase cada, com a Round em que foram escritas) e os `row_id` de até 10 Pool Flows
escolhidos como Examples. `state.instructions`, `state.columns`, `state.categories`, o texto das duas
questions e o corte em 0,5 são protocolo, e nenhum Context os toca. A versão 0 é a linha de base: sem
playbook e sem Examples escolhidos.

`Context` é *frozen*. As versões são guardadas lado a lado — uma proposta recusada continua legível ao
lado da que a venceu — então nenhuma pode ser mutada depois de escrita.

### ▸ Por que um Context vira um arquivo de prompt em vez de ser passado adiante

`Context.to_prompt(template)` devolve `{"text": ..., "sha256": ...}`, exatamente o formato que
`run.load_prompt` já devolvia no projeto base. Isso não é conveniência: é o que mantém intacta **toda
a maquinaria de rastreabilidade do projeto base**. `JevDetector(ctx.to_prompt(t))` simplesmente
funciona, e cada linha de Prediction carrega o `prompt_hash` daquela versão. Uma linha pode sempre ser
rastreada até o Context exato que a produziu, e duas Runs que pediram coisas diferentes nunca são
comparadas como iguais.

Se o Context fosse um objeto passado ao Detector, o `prompt_hash` teria de ser inventado em algum
lugar — e um hash inventado é um hash em que ninguém pode confiar.

A serialização preserva a ordem de chaves do template em vez de ordenar. Ordenar teria reordenado
`state.categories` no instante em que um playbook aparecesse, e então a versão 0 e a versão 1
difeririam **pela ordem em que as Categorias são oferecidas** além de diferirem pelo playbook. Essa
diferença cairia dentro de toda medição de "o curador ajudou".

### ▸ Por que um playbook vazio tem de renderizar o template commitado byte a byte

```python
if not self.rules:
    return {"text": template, "sha256": hashlib.sha256(template.encode("utf-8")).hexdigest()}
```

O `json.loads` acima dessa linha existe só como guarda; o resultado é descartado. **A versão 0 tem de
hashear para exatamente o que o template commitado hasheia**, porque é assim que a primeira Round de
toda Run da Arena é *a mesma coisa* que uma Run publicada em `results/paper/` naquele k. Se a versão 0
renderizasse um re-serializado do arquivo — mesma semântica, bytes diferentes por causa de indentação
ou ordem — o `prompt_hash` mudaria, e a comparação com os números do orientador estaria perdida por
uma diferença que não significa nada.

O mesmo vale para o braço `examples_only` da medição final: os Examples escolhidos viajam como
argumento de `predict`, nunca pelo template, então aquele braço renderiza o template commitado byte a
byte igualzinho à linha de base, e os dois diferem **nos Examples mostrados e em absolutamente mais
nada**.

### ▸ Por que a cláusula que aponta para `playbook` é escrita pelo renderizador e nunca pelo curador

```python
PLAYBOOK_CLAUSE = "  Take `playbook` into account as well."
```

Três razões, e todas as três importam.

1. **Ela precisa existir.** As questions nomeiam em crases os caminhos de `state` que leem. Um
   `state.playbook` que nenhuma question nomeia é **inerte**: o modelo nunca é mandado olhar para
   ele. Um curador cujas Rules nunca foram lidas pareceria inofensivo quando na verdade nunca foi
   ouvido, e o experimento mediria a coisa errada dez Rounds seguidas.
2. **Ela não pode ser do curador.** A regra do projeto é que o curador não escreve texto de question.
   Se ele pudesse, escreveria uma cláusula melhor a cada Round, e "o playbook ajudou" viraria "o
   curador aprendeu a escrever cláusulas".
3. **Ela é fixa e idêntica em toda versão que tem Rules**, portanto **cancela** em qualquer
   comparação entre dois Contexts com playbook. A redação é neutra de propósito: uma cláusula que
   puxasse para `attack` subiria a taxa de alerta sozinha e confundiria toda Round.

**Sem isso:** ou o playbook é invisível, ou vira um segundo canal pelo qual o curador mexe no
protocolo.

---

## `config.py` — os botões

**Problema.** Rounds, tamanhos, orçamento e braços de ameaça precisam mudar sem tocar em código, e uma
configuração que discordou do código precisa falhar **alto**.

Uma dataclass congelada por seção do TOML, cada campo com seu default — por isso
`configs/arena.toml` pode declarar todos os defaults e ser, ele próprio, a documentação do que se pode
mudar. Uma chave que a Arena não conhece, uma seção que não existe, uma fração fora de [0, 1] ou um
valor fora do conjunto permitido **levantam no carregamento**, não são ignorados. As sobrescritas de
linha de comando passam pelos mesmos dois checadores, porque um `--detector` mal digitado que rodasse
silenciosamente o outro Detector seria o pior tipo de erro: a Run terminaria, pareceria saudável e
responderia a uma pergunta que ninguém fez.

---

## `budget.py` — o teto duro

**Problema.** A Arena é um laço que decide sozinho quantas chamadas fazer. Um atacante que erra sempre
gasta `max_queries_per_flow` em cada Flow; um curador a quem se pedem duas propostas pergunta duas
vezes. É exatamente assim que um experimento morre pela metade.

Dois contadores, dois tetos, e o gasto é **reservado antes da chamada**: `spend_detector()` levanta
`BudgetExhausted` em vez de deixar passar. O contador só se move quando o lote inteiro cabe.

Não existe contador em nível de módulo: um `Budget` pertence à Run que o possui, então duas Runs no
mesmo processo nunca comem os créditos uma da outra.

**Por que isso é necessário e não paranoia.** Em 22/09/2026 a execução do Jev perdeu as células de
`k = 16` quando os créditos da TypeSafe acabaram (`docs/protocol.md`, *"k stops at 8"*), e o protocolo
foi cortado em vez de recomprado. O `Budget` torna a parede explícita e bate nela **na pilha do
chamador**, onde a Round ainda pode ser fechada e escrita em disco.

---

## `attacker.py` — mimetismo restrito por substituição de donor

**Problema.** Um atacante não escreve valores de feature do NSL-KDD. As 19 features baseadas em tempo
e em host são recalculadas pelo *sensor* a partir do log de conexões do atacante
([`evasion-constraints.md`](evasion-constraints.md) §4; Apruzzese et al.: *"the actual features ...
are specified only at inference time"*).

### ▸ Por que o atacante copia o bloco de um donor em vez de calculá-lo

O primeiro projeto era paramétrico: girar botões de comportamento (mais devagar, mais espalhado) e
**derivar** as 19 features deles. [`empirical-constraints.md`](empirical-constraints.md) matou esse
projeto com duas medições:

1. **Três das quatro identidades de acoplamento que tal modelo teria de respeitar são contraditas
   pelo Pool** — violadas em **27,5% a 60,5%** dos 125.973 Flows. `count` e `srv_count` não são um par
   aninhado: são **duas janelas paralelas**, uma sobre conexões ao mesmo *host*, outra ao mesmo
   *serviço*. `srv_count > count` em 22% do Pool. Os `dst_host_*` saturam em 255. Um modelo que
   escrevesse `diff_srv_rate := 1 − same_srv_rate` produziria Flows que o sensor não poderia emitir —
   e fabricaria sucesso de evasão em silêncio.
2. **O NSL-KDD não tem timestamps nem ordenação de conexões**, então o log não pode ser reproduzido e
   *nenhuma* direção causal das features derivadas pode ser falseada a partir do CSV (§7, que marca
   toda direção como `support: synthesis`).

Valores derivados sintetizados seriam números cuja consistência conjunta ninguém consegue checar, e um
revisor estaria certo em descartá-los.

**A solução.** O atacante nunca escreve um valor derivado. Ele toma o **bloco inteiro** de um único
Flow benigno real do Pool — um **donor**, um registro que o sensor de fato emitiu — e mantém as
features fixas do ataque, as que fazem de um `guess_passwd` um `guess_passwd`. Sejam quais forem os
acoplamentos verdadeiros, **um bloco real os satisfaz por construção**: o `flag` chega ao lado das
taxas de erro que ele fixa, e `same_srv_rate` ao lado do `count` e do `srv_count` dos quais é uma
fração. É a projeção no espaço-problema de Pierazzi et al., com as *side-effect features* chegando
como um pacote de uma observação real em vez de escolhidas uma a uma.

O bloco vem de **um** donor e nunca é misturado: dois donors emendados reconstroem exatamente a
inconsistência que todo o projeto evita.

**Três filtros estreitam quem pode doar**, cada um fechando um jeito de emitir um Flow que o sensor
não poderia ter produzido:

| Filtro | Regra | Por quê |
|---|---|---|
| `admissible` | o donor tem de rodar o **mesmo `service`** do ataque, e seu `service` e seu `flag` têm de existir naquele `protocol_type` | metade do bloco é calculada sobre janelas do mesmo serviço. Um `guess_passwd` em telnet vestindo `srv_count` e `dst_host_srv_count` de um donor http não é um Flow que sensor nenhum produziu. Isto torna inalcançável o caso de falha de Sheatsley et al. — trocar um `ftp` TCP por `tftp_u`, que é UDP |
| `reachable` | nenhuma das quatro contagens de conexão do donor pode exceder as do ataque | um atacante não pode *afirmar* conexões que nunca fez. Desacelerar e espalhar **afina** janelas; acelerar não é jeito de se esconder |
| `VICTIM_WRITES` | `dst_bytes` fica com o ataque, seja qual for o papel que o modelo lhe dá | quem escreve é a **vítima**. A resposta de um servidor telnet a uma tentativa de login não muda porque o atacante esperou mais entre tentativas; um valor de donor afirmaria uma resposta que nunca houve |

Só os dois levers `direct` são escritos à mão: `src_bytes` (bytes de lixo) e `duration` (latência),
**só para cima** e dentro dos limites medidos por Categoria.

**A busca** tem duas fases: uma sondagem por bucket de donor utilizável, com os levers em zero — *há
alguma forma de comportamento benigno dentro da qual este ataque possa se esconder?* — e depois uma
escalada dos dois levers a partir do bucket escolhido, uma coordenada por vez, só para cima. Qualquer
fase para no instante em que o Verdict vira.

Com `observes = "verdict"` **não há gradiente nenhum**: nenhuma sondagem falha se distingue de outra,
então o bucket é o primeiro utilizável na ordem fixa dos Donors e a escada de levers é percorrida
inteira. Isso é uma enumeração, e dizer isso é o ponto — uma busca que se servisse do `p_attack`
assim mesmo superestimaria o que um atacante caixa-preta consegue fazer.

### ▸ Por que uma Strategy transfere e um Flow mutado não

O que o atacante devolve é uma **`Strategy`**: `bucket` + `padding_bytes` + `added_seconds`. Não é um
Flow mutado, e a diferença é o experimento inteiro.

Uma Strategy nomeia um **bucket de comportamento**, não um donor. O donor é sorteado *por Flow*,
porque quais donors são `reachable` e `admissible` depende do Flow de ataque sendo mutado. Por isso a
mesma Strategy aplicada a um Flow retido é **o mesmo comportamento**, e não o mesmo vetor de features.

É disso que depende o teste de generalização do gate: o gate julga o Split `arena-val`, que o curador
nunca viu, com as Strategies **desta Round**. Um Context que só decorou os vinte Flows atacados
naquela Round tem de falhar nos 250 Flows retidos. Com um Flow mutado no lugar da Strategy não
haveria nada para replicar, o gate mediria memorização, e o experimento não responderia nada.

**O que nada disso conserta, e deve ser dito junto com os resultados.** Vinte das quarenta e uma
features chegam do registro de outra pessoa. Depois dos três estreitamentos o bloco é
serviço-casado, consistente com a vítima e limitado em contagens, mas continua sendo *o tráfego de
outro host usado como disfarce*. A taxa de evasão é em parte uma afirmação sobre **quanto do vetor de
features é entregue de bandeja**, e não sobre a habilidade do atacante. E o filtro `reachable` é uma
**suposição** — o elo mais fraco do modelo inteiro — porque repousa na semântica publicada da
derivação e é intestável neste conjunto de dados.

---

## `analyst.py` — o analista simulado

### ▸ Por que o analista tem orçamento

Porque um SOC real rotula uma fração do que vê, **e é essa escassez que torna o laço adversarial**. O
curador só aprende do que o analista olhou.

Sem orçamento, o curador receberia os rótulos verdadeiros de toda a Round, o atacante não teria onde
se esconder, e o laço mediria uma defesa que não existe em lugar nenhum. O orçamento é a ameaça, não
uma limitação do simulador.

A fila de alertas é **truncada por ranking**, não amostrada: ordenada por `p_attack` decrescente e
cortada em `alert_budget = 50`. A cauda da fila nunca é olhada — que é o que uma equipe escassa de
fato faz.

E há o outro canal, que é o que impede o laço de virar câmara de eco: **`sample_rate` dos Flows que
não geraram alerta é revisado assim mesmo**. Sem ele, um ataque que o Detector perdeu jamais poderia
ser aprendido, porque nada o traria à atenção de ninguém. **Essa amostra é o único caminho pelo qual
uma detecção perdida vira conhecimento.** Faça a aritmética da observabilidade com os números de
`configs/arena.toml` — ela é dura, e está nos comentários de `configs/arena-offline.toml`.

`delay(feedback, round, delay_rounds)` corta o que o curador da Round *n* pode ver: nada observado
depois de *n − 1*. Rotular leva tempo. Um curador que já enxerga a Round à qual vai reagir recebeu a
resposta pronta, o que lisonjeia a defesa e esconde quanto terreno o atacante ganha enquanto a fila é
trabalhada.

`poison()` é a AMEAÇA A2: relabela uma fração do Feedback sobre Flows que realmente são ataque como
benigno. Um adversário que alcança o canal de rotulagem — um insider, um processo de reclamação de
falso positivo em que o defensor confia — **nunca precisa tocar no Detector**: ensinar ao curador que
um ataque era benigno escreve o ponto cego dentro do próprio Context, onde ele sobrevive a todas as
Rounds seguintes.

### ▸ Por que `for_curator` existe

```python
def for_curator(feedback): ...  # row_id, label, detector_verdict, p_attack — e nada mais
```

É uma **projeção**, e é a fronteira, não uma convenção.

- `true_category` nunca a atravessa. Se atravessasse, o curador aprenderia em silêncio de uma verdade
  que o analista nunca reportou, e **o orçamento de rótulos deixaria de significar qualquer coisa** —
  o experimento inteiro mediria um curador onisciente.
- `poisoned` nunca a atravessa. Se atravessasse, o curador poderia descartar as entradas adulteradas e
  **a AMEAÇA A2 não seria ameaça nenhuma**.

Todo curador lê o Feedback por esta função, de modo que o vazamento é **impossível de escrever** em
vez de proibido por um comentário. O reforço é estrutural: a dataclass `Evidence`, em `curator.py`,
não tem campo para nenhum dos dois, e `curator.py` não importa `analyst.py`. Um round loop que
quisesse passar a verdade não teria onde colocá-la.

---

## `curator.py` — a etapa de aprendizado

**Problema.** O curador é a parte inédita do projeto: um Detector cujo prompt melhora a cada Round em
vez de um modelo que retreina. Mas "o LLM ajudou" só é uma afirmação se houver algo sem LLM para
comparar.

Duas implementações, mesma interface:

- **`LLMCurator`** — um Agent do Agno por chamada, sem memória entre Rounds, com `output_schema`
  tipado. Uma resposta de LLM é **dado vindo de fora**: `resolve()` conserta o que dá, descarta o que
  não dá, e escreve a perda no `note` da Proposal. Nenhuma Rule não checada e nenhum `row_id`
  inventado chega a um Context. Um erro de provedor nunca é levantado e nunca vira um playbook
  silenciosamente vazio: não devolve proposta, a Round mantém o Context que já tinha, e `last_error`
  diz o que houve.
- **`HeuristicCurator`** — **a linha de base que mantém a afirmação honesta.** Sem modelo, sem chave,
  **sem uma única Rule**: só escolhe quais Pool Flows mostrar como Examples, sorteados entre os que o
  Detector perdeu. Se acrescentar os Flows perdidos como Examples faz tão bem quanto o raciocínio do
  LLM, **não havia raciocínio a relatar**.

O heurístico responde com tantas Proposals quantas lhe pedirem, e não uma. Uma linha de base
entregando uma Proposal contra duas do LLM perderia parte de toda Round para o tamanho da amostra e
não para o raciocínio — que é a única comparação para a qual essa classe existe.

**A shortlist é evidência, não encanamento.** Os Examples de um Context têm de ser Pool Flows, mas as
falhas acontecem no Split de aprendizado, então nenhum curador consegue oferecer o Flow perdido em si;
o que consegue oferecer é um Pool Flow que se pareça com ele. Sorteada uniformemente sobre 125.973
Flows, essa semelhança é coincidência: **a linha de base heurística fica aleijada, o LLM vence por
omissão, e o resultado de manchete é um artefato do sorteio**. Por isso o sorteio é por registro
perdido, da Categoria que o analista reportou para ele, é **o mesmo sorteio para qualquer curador**, e
a regra exata vai escrita em toda linha de `rounds.jsonl`. Os três números que a definem
(`SHORTLIST_PER_MISS`, `SHORTLIST_UNIFORM`, `SHORTLIST_CAP`) estão no código e **fora do TOML de
propósito**: um botão convidaria uma Run a diferir.

---

## `gate.py` — o portão de aceitação

**Problema.** O curador propõe e alguém precisa dispor. Recall é o número que o laço empurra, e um
Context que o aumenta alertando sobre tudo **parece progresso enquanto destrói o sistema** para o
tráfego legítimo em que também alerta.

A regra guardada: recall não pode cair além de `recall_slack`, e a taxa de alarme falso não pode subir
mais que `false_alarm_slack`. Taxas e não contagens, porque uma Round pode julgar qualquer número de
Flows. Todo caso que ele **não consegue medir é uma recusa** e nunca uma aceitação silenciosa: um
Context cujo custo não pôde ser medido não foi mostrado ser seguro, e o movimento seguro mais barato é
manter o que já está em vigor.

`integrity()` roda nos dois modos, inclusive com o gate desligado, e é a razão pela qual `error_rate`
é contado pelo campo `error` e não pela ausência de Verdict: um Context que faz as chamadas
*falharem* — estourando a janela de contexto, provocando recusas — compra uma taxa de alarme falso
perfeita respondendo nada, e sob o braço fail-closed compra um recall perfeito do mesmo jeito.

### ▸ Por que o gate pontua num Split retido

Os dois Contexts são pontuados sobre `arena-val` (250 Flows), **nunca** sobre `arena`, de onde saem as
Rounds e o Feedback do analista. Aceitação medida naquilo a que o curador foi ajustado não é
aceitação: é o curador se avaliando. E o conjunto de avaliação é o Split retido **passado pelas
Strategies desta Round**, o que faz dele um teste de generalização — o Context novo pega a técnica do
atacante em Flows que o curador nunca viu, ou apenas decorou os que viu?

### ▸ Por que McNemar pareado e não uma comparação crua de recall

Porque julgar os mesmos Flows duas vezes torna a comparação **pareada**, e só os pares discordantes
distinguem dois Contexts ([`CONTEXT.md`](../../CONTEXT.md), *"Discordant pair"*). Os Flows em que
ambos alertaram, e os que ambos perderam, não carregam informação sobre qual é melhor.

Com `recall_slack = 0.0` — a regra estrita — uma comparação crua faria *rollback* de um Context por um
único Flow de diferença. Os números do próprio `gate.py`: perder seis Flows de ataque e ganhar nenhum
dá p = 0,031, uma queda real; perder **quatro** e ganhar nenhum dá **p = 0,125**, que é o que os
mesmos dois Contexts fariam de novo por acaso. Fazer rollback disso seria perseguir ruído durante dez
Rounds.

Então a queda de recall só conta contra o candidato quando é **maior que o slack E** mais do que o
teste pareado consegue atribuir ao acaso. As duas configurações se leem juntas: o slack zero é o que
torna a regra estrita, e o teste pareado é o que impede essa estritez de disparar em ruído.

**A regra que o laço não pode quebrar:** uma chamada de `evaluate` **por semente**. `pairing()` exige
cada `row_id` uma vez por lado; sementes agrupadas caem silenciosamente na regra não pareada e o teste
de McNemar se perde. E um Flow mutado **mantém o `row_id` do pai**, para que o pareamento case; a
Strategy viaja ao lado dele no registro da Round, nunca dentro do `row_id`.

---

## `loop.py` — a Round

Implementa os cinco passos de [`loop-design.md`](loop-design.md) e é o único lugar da Arena onde uma
chamada ao Detector acontece — todas por `Bench.judge`, que é o que faz do Budget um teto real e não
uma esperança.

As sondagens do atacante **não** são escritas em `predictions.jsonl`: são o mesmo Flow julgado até 30
vezes sob mutações depois descartadas, e escrevê-las multiplicaria as linhas de um Flow e moveria em
silêncio toda taxa que `jev_ids.metrics` calcula sobre o arquivo.

`project()` calcula o pior caso da Run inteira **antes da primeira chamada** e recusa uma Run que não
consegue terminar, **antes de criar o diretório**. Três termos, não dois — uma versão anterior deste
comentário omitia o tráfego da própria Round e o lado do titular no gate, e subcontava em 8.000.

`Draft` é preenchido **passo a passo**, não no fim: uma Round cortada por `BudgetExhausted` ainda
escreve tudo o que alcançou. O `Round` do atacante vale a leitura mesmo que o gate nunca tenha rodado.

Cada semente é uma **linhagem independente**: seu próprio Context, sua própria fila de Feedback, seu
próprio contador de versões, seu próprio atacante e curador. Um vazamento entre sementes tornaria as
sementes correlacionadas e a dispersão entre elas, sem sentido.

---

## `records.py` — os quatro arquivos

`config.json` diz **o que foi rodado** (config resolvida, os sha256 de todas as entradas, a projeção,
o snapshot do Budget, o commit do código) e é escrito **antes da primeira chamada**. `rounds.jsonl`
diz **o que aconteceu**, uma linha por (seed, Round), anexada no instante em que a Round fecha.
`predictions.jsonl` carrega as Predictions no formato ordinário do projeto base — mais `round`,
`context_version` e `arena_stage` — para que `jev_ids.metrics` leia uma Run da Arena sem caso especial.
`contexts.jsonl` guarda **todo Context já proposto, aceito ou não**: sem as recusadas, uma Run que
rejeitou quinze Contexts é indistinguível de uma que não propôs nenhum.

A disciplina é a do `run.execute`, pela mesma razão: uma Round custa centenas de chamadas, e uma Run
que bufferizasse as Rounds até o fim perderia todas de uma vez.

---

## `report.py` — as tabelas do laço

Três regras valem em todo lugar aqui.

1. **Recall nunca aparece sem `input_tokens` médio ao lado.** Um Context curado também é um prompt
   mais **longo**, e prompts mais longos movem as respostas de um modelo por conta própria.
2. **A evidência é uma amostra enviesada com contagens não enviesadas.** `misses` e `false_alarms` são
   da Round inteira, enquanto o analista revisou `analyst_reviewed` Flows dela. As duas ficam na mesma
   linha, para que uma Categoria que *parece* rara possa ser distinguida de uma em que o analista
   nunca chegou.
3. **Runs medidas sobre Flows diferentes não são uma comparação.** `compare_runs` **recusa** um
   conjunto de Runs que difiram no Card, nos Splits, no atacante, no template do prompt, no Detector,
   no k ou no número de Rounds, e diz o que difere em vez de tirar média. Card, Splits e prompt são
   comparados por **sha256 e nunca por nome de arquivo**; uma Run que não registrou hash nenhum também
   é recusada, porque uma checagem que não pôde rodar não é uma checagem que passou.

Nada aqui recalcula uma pontuação: recall, F1, taxa de erro, teste pareado e preços vêm todos de
`jev_ids.metrics`, o mesmo código das outras tabelas do artigo, de modo que os números da Arena não
podem divergir deles.

---

## `final.py` — a medição que pode ser citada

### ▸ Por que a avaliação final precisa de quatro braços

**Nem a Round nem o gate produzem um número que alguém deva citar.** Ao longo de uma Run, a versão 0 e
o Context final estiveram em vigor em **Rounds diferentes contra mutações diferentes**: duas
Predictions delas compartilham um `row_id` e **não** o tráfego por trás dele. Aqui, todo Context julga
os **mesmos** Flows do Split de avaliação intocado, uma semente por vez, então a comparação é
genuinamente pareada e continua comparável com `results/paper/`.

Quatro braços porque **um Context curado muda três coisas ao mesmo tempo**: quais Examples o Detector
vê, quão longo é seu prompt, e o que o playbook de fato diz. Cada braço congela mais uma delas, então
as quatro linhas se leem como três passos:

| Passo | O que isola |
|---|---|
| `baseline` → `examples_only` | **os Examples.** O playbook vazio da versão 0 carregando os `example_ids` do Context final. Como Examples escolhidos viajam pelo argumento de `predict`, o prompt é o template commitado byte a byte nos dois braços |
| `examples_only` → `placebo` | **o comprimento do prompt**, Examples constantes. Um playbook viaja em toda chamada ao Detector; sem este passo, *"o playbook ajudou"* não pode ser distinguido de *"mais texto ajudou"* |
| `placebo` → `final` | **o conteúdo das Rules**, comprimento e Examples constantes. É o número que o projeto inteiro existe para produzir, e não pode ser lido sem os outros três |

O placebo é gerado **a partir da forma do Context final** por `placebo_rules` e **nunca** por um
curador: este módulo não faz chamada de curador nenhuma, e seu Budget é criado sem nada para gastar
nelas — um teto, não um comentário. O catálogo de frases está em `PLACEBO_SENTENCES`, auditável linha
a linha: cada frase é verdadeira sobre redes, nenhuma nomeia uma Categoria ou uma feature do Card, e
nenhuma ajuda a decidir nada. Os comprimentos formam uma escada de 30 a 203 caracteres, e cada Rule
real recebe a frase de comprimento mais próximo.

**O Split inteiro é julgado, e não só as Categorias atacadas.** Um curador que sobe o recall nas
Categorias sob ataque ensinando o Detector a desconfiar de sessões silenciosas mexe em todas as
outras, e uma medição restrita às atacadas nunca mostraria isso. É para isso que servem as colunas
`recall_<categoria>`, `recall_mutated` e `recall_unmutated`.

---

## `detectors/jev.py` e `detectors/offline.py`

`JevDetector` é do projeto base e não foi tocado: um Flow por requisição, duas questions tipadas,
política de retentativa própria, e uma chamada que falha vira uma linha com `error` em vez de uma
exceção.

`OfflineDetector` é uma Random Forest **vestindo o `prompt_hash` do Context**. Ele existe para
exercitar o encanamento sem chave e sem custo, e reage a um Context novo exatamente onde a Arena
precisa: mudando o `prompt_hash` de toda linha que escreve. **Uma floresta não lê playbook**, então
nenhuma Rule do curador pode mover uma única resposta dela. Está escrito em maiúsculas na docstring do
módulo e vale repetir: qualquer curva medida contra ele descreve o encanamento e nada mais.

---

## O que o sistema registra que **parece** resultado e não é

Esta seção é a mais importante do documento para uma prova oral. Cada item está escrito no código, nas
docstrings de `loop.py`, `report.py` e `final.py`; estão reunidos aqui.

### Do laço (`loop.py`)

1. **Recall lido em `gate_split` é uma curva de treino vestida de conjunto de teste.** Cada proposta
   foi medida contra o **titular** e nunca contra as outras propostas, então a escolha entre dois
   Contexts aceitos é uma comparação que o gate **nunca rodou** — e é feita no próprio Split em que o
   gate os mediu. Com dez Rounds e duas propostas, uma Run seleciona sobre `arena-val` **vinte vezes**,
   e o recall do vencedor ali está enviesado para cima exatamente por essa seleção. O número retido de
   uma Run terminada é o medido em `eval_split`, pelo comando final separado.
2. **`misses` e `false_alarms` são da Round inteira; o analista viu uma fatia.** Um curador pode
   concluir que uma Categoria é rara quando o analista simplesmente nunca chegou nela. Leia sempre
   `analyst_reviewed` na mesma linha.
3. **A taxa de evasão não mede habilidade.** Vinte das quarenta e uma features chegam prontas do
   registro de outro host. Um Detector que se apoia no bloco derivado vira; um que se apoia em
   `service`, `src_bytes` e no bloco de conteúdo não vira. É propriedade do método.
4. **Sob `on_failure = "closed"`, a taxa de erro reportada por `metrics.scores` é zero.** Aquele braço
   escreve o alerta na linha, então o Verdict existe e a contagem do projeto base não vê nada. As
   falhas continuam visíveis no campo `error`, que é onde o gate as conta.

### Das tabelas (`report.py`)

5. **Recall sem `input_tokens` ao lado não distingue "o playbook ajudou" de "mais texto ajudou".** Só
   o braço placebo resolve isso, e só se as duas colunas estiverem ali para serem lidas.
6. **Os braços não são julgados sobre tráfego idêntico.** O atacante de cada braço buscou suas
   mutações contra o Context daquele braço, então duas Predictions sobre um `row_id` são sobre dois
   Flows mutados diferentes. Parear por `row_id` continua sendo o teste certo — é o mesmo Flow pai —
   mas parte de qualquer diferença entre dois braços é dos atacantes deles.
7. **As colunas de Budget são da Run inteira**, contadores cumulativos, repetidos em toda linha por
   semente. **Não se somam.**
8. **Uma comparação em nível de Run não consegue separar conteúdo de comprimento, por construção**,
   porque um playbook placebo é derivado da forma do Context final e não existe até o laço terminar.

### Da medição final (`final.py`)

9. **Seleção, que é a maior ameaça restante ao número de manchete.** O Context `final` é o argmax de
   até `rounds × proposals_per_round` decisões de gate, todas tomadas sobre recall, enquanto o
   `baseline` é um ponto fixo que nunca foi selecionado para nada. **Nada corrige essa multiplicidade**,
   então uma diferença `placebo → final` do tamanho que um argmax de sorte produz não pode ser
   distinguida de uma que as Rules produziram.
10. **As mutações são adaptadas a um braço.** As Strategies replicadas foram buscadas contra o Context
    **final**, então o tráfego mutado é o tráfego que venceu *ele*, e nenhuma busca foi rodada contra
    a versão 0. Isso corre **contra** o braço final, não a favor: nessa dimensão a medição é
    conservadora.
11. **O placebo casa comprimento e tokens, não saliência.** Suas frases são verdadeiras e inertes; uma
    Rule real nomeia features às quais o modelo já está atendendo. Se **nomear** uma feature já move a
    resposta, seja qual for o conselho, este braço não controla isso — uma cópia embaralhada ou negada
    do playbook real seria o controle mais forte.
12. **Uma repetição por Flow.** Cada braço julga cada Flow uma vez, então não há medida da variância
    própria do Detector por baixo do p de McNemar, e uma diferença de poucos Flows pode ser ruído que
    a tabela vai alegremente atribuir ao playbook.
13. **O Detector offline não lê playbook de jeito nenhum.** Com `[detector] name = "offline"` os braços
    `examples_only`, `placebo` e `final` são idênticos **por construção**, e o p = 1 é aritmética, não
    evidência. Alguém vai rodar offline primeiro: **nada naquela tabela é resultado.**

### E, acima de todos

14. **O laço nunca foi rodado contra o Jev.** Até agora só o smoke offline rodou. Não existe resultado
    experimental deste projeto, e [`trabalho-adversarial/README.md`](../../trabalho-adversarial/README.md)
    diz a mesma coisa na primeira página.
