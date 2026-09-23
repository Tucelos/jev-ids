# Como rodar a Arena

Guia operacional, escrito para quem nunca abriu este projeto. Ao final você terá rodado o laço
inteiro sem gastar um centavo, saberá ler os quatro arquivos que uma Run escreve, e saberá o que
precisa acontecer para rodar contra o Jev de verdade.

O protocolo — *o que* o sistema faz — está em [`loop-design.md`](loop-design.md). O *porquê* de cada
peça está em [`arquitetura.md`](arquitetura.md). Aqui só tem comando.

---

## 1. Pré-requisitos

- **Python 3.13.** A versão está fixada em `.python-version`; o `uv` baixa sozinho se faltar.
- **[`uv`](https://docs.astral.sh/uv/)**, o gerenciador de pacotes. Nada mais.
- **`make` não é necessário e não aparece neste guia.** A máquina de desenvolvimento do grupo é
  Windows e não tem `make`. Os alvos do `Makefile` continuam válidos para o orientador, que usa
  macOS; todo comando abaixo é o equivalente direto em `uv`. Isso é a pendência 6 de
  [`tarefas.md`](tarefas.md).

```bash
cd jev-ids
uv sync
cp .env.example .env
```

O `uv sync` cria `.venv/` e instala tudo, inclusive o comando `jev-ids`. Confira:

```bash
uv run jev-ids --help
```

Devem aparecer seis subcomandos: `run`, `redo-errors`, `metrics`, `compare`, `arena`, `arena-eval`.

---

## 2. Os dados

Baixe o [NSL-KDD do Kaggle](https://www.kaggle.com/datasets/hassan06/nslkdd) e coloque os dois
arquivos de texto em `data/raw/nsl-kdd/`:

```
data/raw/nsl-kdd/KDDTrain+.txt
data/raw/nsl-kdd/KDDTest+.txt
```

Prepare uma vez:

```bash
uv run python -m scripts.prepare_nsl_kdd
```

Isso escreve `data/nsl-kdd/pool.csv` (125.973 Flows, o Pool de onde saem os Examples e os donors) e
`data/nsl-kdd/test.csv` (22.544 Flows, de onde os Splits foram sorteados). Os dois são ignorados pelo
git, por isso precisam ser gerados; **tudo o mais já está versionado**:

- `data/nsl-kdd/splits/arena.csv` (550 Flows), `arena-val.csv` (250), `paper.csv` (2.000) e os
  demais, com a proveniência em `splits/SOURCE.json`;
- `data/nsl-kdd/mutations.json`, o modelo de restrições que o atacante obedece, já ajustado por
  `scripts/fit_mutations.py`.

Não é preciso sortear Split nenhum nem reajustar o modelo. Se algum dia for:

```bash
uv run python -m scripts.fit_mutations
uv run pytest tests/test_mutations.py
```

---

## 3. Variáveis de ambiente

Estão todas em `.env.example`, com um comentário cada. Copie para `.env` (que o git ignora) e
preencha **só o que você for rodar**. Nada aqui é lido na importação: um Detector ou um curador pede
sua chave na primeira chamada.

| Caminho | Variáveis necessárias | Observação |
|---|---|---|
| **Smoke offline** (`configs/arena-offline.toml`) | **nenhuma** | Detector é uma Random Forest local, curador é heurístico. Zero chamadas pagas. |
| **Run real** (`configs/arena.toml`) | `TYPESAFE_API_KEY` **e** `DEEPSEEK_API_KEY` | A primeira é do Detector (Jev), a segunda é do curador LLM. Faltando qualquer uma, veja a §9. |
| Curador em outro provedor | `OPENAI_API_KEY` ou `OLLAMA_HOST` | Troque `[curator] provider` no TOML. O Ollama roda local e não precisa de chave. |
| Jev pelo AI Gateway da Vercel | `JEV_GATEWAY=vercel` e `AI_GATEWAY_API_KEY` | Caminho alternativo, usado nas execuções do orientador até 21/09. |
| Linhas de base do orientador | `GOOGLE_*` (Gemini/Vertex), `CHATGPT_*` | Não são usadas pelo laço. Pendências 1 e 2 de [`tarefas.md`](tarefas.md). |

---

## 4. O smoke sem chave nenhuma

Antes de gastar qualquer chamada paga, veja o que a Run pretende gastar:

```bash
uv run jev-ids arena --config configs/arena-offline.toml --dry-run
```

```json
{
  "attacker_calls_per_seed_per_round": 200,
  "traffic_calls_per_seed_per_round": 550,
  "gate_calls_per_seed_per_round": 750,
  "rounds": 2,
  "seeds": 1,
  "detector_calls": 3000,
  "max_detector_calls": 5000,
  "curator_calls": 2,
  "max_curator_calls": 20,
  "fits": true
}
```

`"fits": true` é a licença para começar. Rode:

```bash
uv run jev-ids arena --config configs/arena-offline.toml
```

Leva cerca de 35 segundos e imprime uma linha por Round:

```
seed=0 round=1 evaded=2/10 proposals=0 context=v0 calls=643
seed=0 round=2 evaded=1/10 proposals=2 context=v0 calls=2044
done: results/arena-offline/20260923T202625.601654Z-nsl-kdd-offline-heuristic
```

### O que essa saída significa, palavra por palavra

- **`evaded=2/10`** — o atacante recebeu 10 Flows de ataque e conseguiu que o Detector parasse de
  alertar em 2. Taxa de evasão de 0,2. O número varia com a semente e com o Detector; não é uma
  medida de nada.
- **`proposals=0` na Round 1** — **correto, não é bug.** `[analyst] delay_rounds = 1` significa que o
  curador da Round *n* só enxerga rótulos observados até a Round *n − 1*. Na Round 1 não existe Round
  0, então o curador recebe Evidence vazia e responde com nada. O primeiro curador de verdade é o da
  Round 2.
- **`context=v0`** — o Contexto em vigor ao fim da Round. Continuou sendo a versão 0, a linha de base
  sem playbook e sem Examples escolhidos, porque o portão não aceitou nenhuma proposta.
- **`calls=643`, depois `2044`** — o contador cumulativo de chamadas ao Detector da Run inteira. A
  Round 1 gastou 93 sondagens do atacante + 550 de tráfego = 643, e não tocou no portão porque não
  havia proposta para julgar. A Round 2 gastou 101 + 550 + 750 (portão: 250 Flows × (2 propostas + 1
  titular)) = 1.401, fechando em 2.044.

### O portão recusar tudo é o resultado certo

Abra o `rounds.jsonl` da Round 2 e você encontra, nas duas decisões do portão:

```
reason: false alarms rose from 0.327 to 1.000, 0.673 over the 0.020 allowed
candidate_recall 1.0   incumbent_recall 0.95
candidate_false_alarm_rate 1.0   incumbent_false_alarm_rate 0.327
```

Leia isso como um **sucesso do portão**. O curador heurístico propôs um Contexto com 9 Examples
escolhidos, contra os 40 que o sorteio em `k = 8` sobre cinco Categorias entrega. Uma Random Forest
treinada em 9 linhas chama tudo de ataque: o recall subiu para 1,0 e o alarme falso subiu junto, para
1,0. O portão recusou as duas propostas porque `false_alarm_slack` é 0,02 e a proposta pedia 0,67. Foi
exatamente para isso que ele existe.

**Uma Run offline em que o portão aceita tudo seria o sinal de alarme**, não o contrário.

### E o que o smoke *não* é

O Detector `offline` é uma Random Forest vestindo o `prompt_hash` do Contexto. **Uma floresta não lê
playbook.** Nenhuma Rule que o curador escreva pode mover uma única resposta dela; só os Examples
escolhidos podem. Qualquer curva medida aqui descreve o encanamento do laço e nada mais. O próprio
`configs/arena-offline.toml` diz isso no cabeçalho, e `jev_ids/detectors/offline.py` repete em
maiúsculas.

---

## 5. Os quatro arquivos que uma Run escreve

Estão em `results/arena/<run_id>/` (ou `results/arena-offline/<run_id>/` no smoke). Cada um responde
uma pergunta diferente, e o `config.json` é escrito **antes da primeira chamada**, de modo que uma Run
morta por falta de crédito ou por tampa de notebook fechada ainda é legível.

### `config.json` — o que foi rodado

- `config`: as oito seções do TOML já resolvidas, com os valores efetivos (inclusive os que vieram de
  `--rounds`, `--seeds` ou `--detector`).
- `inputs`: o **sha256** do Card, do learn split, do gate split, do template do prompt, do prompt do
  curador e do `mutations.json`. É por aqui que se prova que duas Runs julgaram os mesmos Flows —
  nunca pelo nome do arquivo.
- `projection`: a projeção de custo do pré-voo, com `fits`.
- `budget`: o snapshot do orçamento no instante em que a Run começou (zerado).
- `code_commit`: o commit do código, com `-dirty` se a árvore de trabalho tinha mudanças.

### `rounds.jsonl` — o que aconteceu, uma linha por (seed, Round)

Cada linha traz `context` (o Contexto em vigor enquanto o tráfego foi julgado) e `prompt_hash`, mais
cinco blocos:

| Bloco | O que ler nele |
|---|---|
| `attack` | `flows`, `evaded`, `evasion_rate`, `queries` e uma entrada por Flow atacado em `strategies` (com `bucket`, `padding_bytes`, `added_seconds`, `start_p_attack`, `final_p_attack`) |
| `analyst` | `reviewed`, `alerts_reviewed`, `quiet_reviewed`, `poisoned`. **Compare sempre com os `misses` da Round inteira**: o curador pode concluir que uma Categoria é rara quando o analista simplesmente nunca chegou nela |
| `shortlist` | `size` e `how` — a regra exata do sorteio dos Pool Flows oferecidos como Examples. Está escrita em toda linha de propósito: esse sorteio decide o experimento |
| `curator` | `kind`, `model`, `proposals`, `error`, `notes`. `error` preenchido e `proposals: 0` é um curador que falhou; a Round manteve o Contexto que já tinha |
| `gate` | Uma entrada por proposta, com `version`, `accepted`, `reason` (uma frase escrita para um humano ler, em inglês como o resto do código) e todos os números da decisão: os dois recalls, as duas taxas de alarme falso, `mcnemar_p`, `candidate_only_hits`, `incumbent_only_hits` |

Mais `accepted_version` (a versão em vigor depois do portão — a do titular quando nada foi aceito) e
`budget` (o gasto acumulado da Run quando a Round fechou; **é da Run, não da seed, e não se soma**).

### `predictions.jsonl` — as Predictions em si

Exatamente o formato do `jev_ids.records` do projeto base, para que `jev_ids.metrics` leia sem caso
especial, mais três campos: `round`, `context_version` e `arena_stage`. O `arena_stage` é um de
`traffic`, `gate-candidate` ou `gate-incumbent`. **As sondagens do atacante não estão aqui**: seriam o
mesmo Flow repetido até 30 vezes sob mutações descartadas, e multiplicariam cada taxa do arquivo.

### `contexts.jsonl` — todo Contexto já proposto, aceito ou não

Uma linha por proposta, com `seed`, `round`, `accepted` e o Contexto (`version`, `rules`,
`example_ids`, `parent`, `note`). As recusadas ficam ali de propósito: sem elas, uma Run que rejeitou
quinze Contextos é indistinguível de uma que não propôs nenhum.

---

## 6. A Run de verdade

```bash
uv run jev-ids arena --dry-run                    # confira antes
uv run jev-ids arena --config configs/arena.toml  # o padrão já é configs/arena.toml
```

Precisa de `TYPESAFE_API_KEY` e da chave do provedor do curador. Sobrescritas úteis para depurar, que
ficam registradas no `config.json` da própria Run:

```bash
uv run jev-ids arena --rounds 2                   # duas Rounds em vez de dez
uv run jev-ids arena --detector offline           # o mesmo TOML contra a floresta
uv run jev-ids arena --seeds 0,1                  # duas sementes (veja a aritmética abaixo)
```

### A aritmética do orçamento

Três termos, por seed e por Round, em chamadas ao Detector:

```
atacante   flows_per_round × max_queries_per_flow      = 20 × 30 =   600   (pior caso)
tráfego    |arena|                                     =     550 =   550
portão     |arena-val| × (proposals_per_round + 1)     = 250 ×  3 =   750
                                                       por Round   = 1.900
× 10 Rounds × 1 seed                                               = 19.000
```

Contra `max_detector_calls = 20.000`. **Cabe, com folga de 1.000 chamadas.** É apertado de propósito.

O termo do atacante é o pior caso: um Flow que evade cedo custa menos, e por isso o smoke gastou 93
sondagens onde a projeção reservou 200.

### Três sementes não cabem, e isso é deliberado

```bash
uv run jev-ids arena --seeds 0,1,2 --dry-run   # "fits": false, 57.000 contra 20.000
uv run jev-ids arena --seeds 0,1,2             # recusa antes de criar diretório nenhum
```

```
BudgetExhausted: this Run cannot finish: detector_calls: 57,000 projected against a cap of 20,000.
Per seed per Round: 600 attacker + 550 traffic + 750 gate = 1,900, over 10 Rounds and 3 seed(s).
Raise the cap in [budget] deliberately, or run fewer seeds, Rounds or queries.
```

O protocolo relatado em [`loop-design.md`](loop-design.md) pede três sementes, e três sementes custam
57.000 chamadas. **O laço se recusa a começar uma Run que não consegue terminar**, antes de criar o
diretório, porque um experimento que morre na Round 7 vale menos que um que nunca foi começado: as
Rounds que ele jogou foram jogadas contra um Contexto que nunca enfrentou as que ele não jogou, e
nenhum braço do protocolo pode ser comparado com ele.

Isso não é cautela abstrata. Em 22/09/2026 a execução do Jev do orientador perdeu as células de
`k = 16` quando os créditos da TypeSafe acabaram, e o protocolo foi cortado em vez de recomprado
(`docs/protocol.md`, *"k stops at 8"*).

Rodar três sementes é, portanto, **uma decisão**, e a decisão se escreve no arquivo: suba
`[budget] max_detector_calls` para pelo menos 57.000 em `configs/arena.toml`, sabendo o que está
comprando. Não há flag de linha de comando para isso, também de propósito.

---

## 7. A medição final

Os números da própria Run não respondem se o curador ajudou: ao longo de uma Run, a versão 0 e o
Contexto final estiveram em vigor em **Rounds diferentes contra mutações diferentes**, então duas
Predictions sobre um mesmo `row_id` são sobre tráfegos distintos. A medição final julga quatro
Contextos sobre **um conjunto idêntico de Flows**, no Split `paper`, que nunca foi aprendido:

```bash
uv run jev-ids arena-eval results/arena/<run_id> --dry-run
uv run jev-ids arena-eval results/arena/<run_id>
```

Custo: 2.000 Flows × 4 braços × nº de sementes. Com uma semente são 8.000 chamadas, contra o
`max_detector_calls` da Run de origem. O comando imprime a tabela em CSV; para reimprimir depois, sem
gastar nada:

```bash
uv run jev-ids arena-eval results/arena/<run_id> --report results/arena-eval/<eval_id>
```

O `run_dir` posicional continua obrigatório mesmo com `--report`.

### Como ler a tabela de quatro braços

Quatro linhas por semente, sempre nesta ordem, porque a ordem **é** a decomposição. Um Contexto curado
muda três coisas ao mesmo tempo — quais Examples aparecem, que tamanho o prompt tem, e o que o
playbook diz — e cada braço congela mais uma delas:

| Passo | O que a diferença mede |
|---|---|
| `baseline` → `examples_only` | **O que escolher os Examples comprou.** O playbook vazio da versão 0 carregando os `example_ids` do Contexto final. O prompt renderizado é byte a byte o template commitado nos dois braços; só os Examples se movem. |
| `examples_only` → `placebo` | **O que o comprimento do prompt comprou.** Tantas Rules quantas o Contexto final tem, de comprimento casado, cada uma verdadeira sobre redes e inútil para esta decisão. Sem este passo, *"o playbook ajudou"* é indistinguível de *"mais texto ajudou"*. |
| `placebo` → `final` | **O que o conteúdo das Rules comprou**, com comprimento e Examples constantes. É o número que o projeto inteiro existe para produzir, e ele não pode ser lido sem os outros três. |

Colunas que não se leem sozinhas:

- **`recall` nunca aparece sem `input_tokens_mean` e `cost_usd_per_1m` ao lado.** Um playbook viaja em
  toda chamada ao Detector, e um braço que ganhou recall enquanto o prompt cresceu são duas hipóteses
  de uma vez.
- **`rules` e `rule_chars`** existem para você conferir que o placebo realmente casou a forma do
  Contexto final, em vez de acreditar no código.
- **`recall_mutated` contra `recall_unmutated`**, e uma coluna `recall_<categoria>` por Categoria. É
  aí, e só aí, que aparece um playbook que comprou recall nas Categorias atacadas estragando outra.
- **`vs_baseline_discordant`, `arm_correct`, `baseline_correct`, `mcnemar_p`** são o teste pareado
  contra o braço `baseline` da mesma semente. O `baseline` é pareado consigo mesmo e por isso reporta
  0 discordantes e p = 1 — o que também é a checagem de que o pareamento está completo.

### No offline, a tabela é degenerada e você deve esperar isso

Rodando `arena-eval` sobre a Run do smoke, as quatro linhas saem **idênticas**, com `mcnemar_p = 1,0`.
Dois motivos somados: o portão não aceitou nada, então o Contexto `final` é a própria versão 0; e a
floresta não lê playbook, então `examples_only`, `placebo` e `final` seriam iguais por construção de
qualquer jeito. Isso é aritmética, não evidência. Alguém do grupo vai rodar offline primeiro: **nada
naquela tabela é resultado.**

---

## 8. As outras tabelas

`summarize_rounds` (uma linha por Round) e `summarize_run` (uma linha por semente, o Contexto final
contra a versão 0) ainda **não têm subcomando na CLI**. Chame de Python:

```bash
uv run python -c "from pathlib import Path; from jev_ids.arena import report; from jev_ids.cli import print_csv; print_csv(report.summarize_rounds(Path('results/arena/<run_id>')))"
uv run python -c "from pathlib import Path; from jev_ids.arena import report; from jev_ids.cli import print_csv; print_csv(report.summarize_run(Path('results/arena/<run_id>')))"
```

`report.compare_runs([...])` põe várias Runs lado a lado — ou **recusa** e diz o que difere, se elas
não julgaram os mesmos Flows sob o mesmo Detector.

---

## 9. Quando der errado

### Sem `TYPESAFE_API_KEY`

```
TypeSafeError: No API key was provided. Pass api_key or set the TYPESAFE_API_KEY environment variable.
```

O SDK recusa antes de qualquer requisição. Preencha `.env`. Para rodar sem chave nenhuma, use
`--detector offline` ou `configs/arena-offline.toml`.

### Sem a chave do curador — o modo caro de falhar

Este é o erro que custa dinheiro, porque **a Run não quebra**. O curador LLM captura toda exceção do
provedor, devolve zero propostas e grava o motivo:

```
curator: {"kind": "llm", "proposals": 0, "error": "provider: DEEPSEEK_API_KEY not set. ..."}
```

A Run continua gastando as 1.900 chamadas ao Detector por Round e termina com `context=v0` em todas as
dez. É por isso que a §3 existe. **Confira as duas chaves antes de rodar**, e se a Run imprimir
`proposals=0` em duas Rounds seguidas com `[curator] kind = "llm"`, mate-a e olhe o `curator.error` do
`rounds.jsonl`.

### Créditos acabaram no meio de uma Round

O `Budget` bate no teto **na pilha do chamador**, onde a Round ainda pode ser fechada e escrita. A Run
imprime

```
seed=0 round=7 stopped: detector_calls: 20000 of 20000 spent, 1 more asked
```

e a Round 7 vai para o `rounds.jsonl` com tudo o que tinha alcançado — o atacante já vale a leitura
mesmo que o portão nunca tenha rodado. Não há retomada: leia `budget` na última linha escrita, decida
o que subir, e recomece. Uma Run que acabou cedo **não é comparável** com uma que jogou as dez Rounds.

### CRLF no Windows

`load_prompt` e o laço hasheiam **bytes**. Um checkout com CRLF muda silenciosamente o `prompt_hash`,
o hash do Card e o hash dos Splits, e a Run deixa de ser comparável com as do orientador — sem
nenhuma mensagem de erro, que é o pior tipo de falha. O `.gitattributes` fixa `* text=auto eol=lf`
justamente para isso. Se você clonou antes disso, ou se o seu git está com `core.autocrlf=true`:

```bash
git config core.autocrlf false
git rm --cached -r .
git checkout .
```

Depois confira que o hash bate. O `inputs.prompt` do `config.json` de uma Run nova da Arena tem de ser
igual ao `prompt_hash` das Runs publicadas do orientador — hoje, para o NSL-KDD, os dois são
`e5704395d8a6c11f814d65f346c258408d7a5724ffbf2ab22e5339a9f8d076b2`:

```bash
uv run python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('prompts/nsl-kdd/jev.json').read_bytes()).hexdigest())"
uv run python -c "import json; print(json.load(open('results/paper/20260922T033245.466422Z-nsl-kdd-jev-paper/config.json'))['prompt_hash'])"
```

Se as duas linhas divergirem, seus arquivos foram convertidos e **nenhum número seu é comparável com
os publicados** até você desfazer isso.

### Erro de digitação no TOML

O `config.py` recusa no carregamento em vez de ignorar em silêncio. As quatro recusas, todas
verificadas:

| O que você escreveu | O que sai |
|---|---|
| `kindd = "heuristic"` em `[curator]` | `ValueError: [curator] has no key kindd; it takes kind, max_examples, max_rules, model, proposals_per_round, provider` |
| `[curador]` | `ValueError: configs/x.toml: no such section: curador` |
| `sample_rate = 4.0` | `ValueError: analyst.sample_rate = 4.0: a share lives in [0, 1]` |
| `kind = "heuristico"` | `ValueError: curator.kind = 'heuristico': one of heuristic, llm` |

O mesmo vale para as sobrescritas de linha de comando: `--detector jevv` é checado com o mesmo código,
porque uma Run que rodasse o Detector errado terminaria, pareceria saudável e responderia a uma
pergunta que ninguém fez.

### O único valor válido que ainda assim falha: `[attacker] kind = "llm"`

`configs/arena.toml` documenta `kind = "llm"` ao lado de `"mimicry"`, e o `check_choices` o aceita —
mas a classe `LLMAttacker` **não existe** em `jev_ids/arena/attacker.py`. A Run carrega a config,
escreve o diretório, monta os donors sobre os 125.973 Flows do Pool e só então levanta:

```
NotImplementedError: attacker kind 'llm' needs LLMAttacker in jev_ids.arena.attacker
```

Use `kind = "mimicry"`, que é o padrão e o atacante que o projeto descreve. O atacante LLM é trabalho
futuro; o comportamento está fixado em `tests/test_arena_loop.py`.

### Uma Run sem Round nenhuma

```
ValueError: <run_id> recorded no Round for any of the seeds [0]: there is nothing to measure
```

`arena-eval` recusa em vez de produzir quatro braços silenciosamente iguais à linha de base.

---

## 10. O portão de qualidade

Sem `make`:

```bash
uvx ruff check . && uvx ruff format --check .
uvx complexipy -q --max-complexity-allowed 15 .
uv run pyright
uv run pytest
```

Os limiares estão em `pyproject.toml`. Os testes não fazem chamada paga nenhuma. O `make check` do
orientador roda ainda `vulture`, `pip-audit` e `jscpd`; as linhas exatas estão no `Makefile`, e as
três precisam de rede.
