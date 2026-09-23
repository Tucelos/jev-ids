# Tarefas pendentes do fork

O que herdamos do repositório do orientador e ainda não mexemos, com a razão de mexer e os arquivos exatos.
Nada aqui é urgente: o projeto roda com tudo no lugar. A decisão foi manter primeiro e limpar depois, para
não quebrar nenhuma comparação com os números publicados enquanto o laço ainda estava sendo escrito.

## 1. Remover o caminho da assinatura do ChatGPT

**Por quê.** `chatgpt.py` fala com um *backend* não oficial do ChatGPT (`chatgpt.com/backend-api/codex`)
usando tokens OAuth do Codex. É frágil, depende de um login que expira, e nós não usamos: o curador e o
detector reserva falam com a **API oficial** da OpenAI, com `OPENAI_API_KEY`. Também é a origem do único
teste que quebrava no Windows.

| Arquivo | Linhas | Ação |
|---|--:|---|
| `jev_ids/detectors/chatgpt.py` | 214 | remover |
| `tests/test_chatgpt.py` | 133 | remover |
| `jev_ids/detectors/llm.py` | — | tirar o ramo `openai` que chama `ChatGPTSubscriptionModel` e trocar por `OpenAIResponses` da API oficial |
| `.env.example` | — | tirar `CHATGPT_CLIENT_ID` e `CHATGPT_TOKEN_PATH` |
| `prices.json` | — | manter `gpt-5.6-luna` e `gpt-5.6-terra` se ainda formos precificar a OpenAI |

## 2. Decidir sobre o caminho Gemini / Vertex AI

**Por quê.** É a linha de base do artigo do orientador (7 ocorrências em `llm.py`) e exige
`gcloud auth application-default login` e um projeto no Google Cloud, que ninguém do grupo tem. Não
atrapalha, mas é peso morto se não formos rodar.

Manter se quisermos reproduzir a comparação Jev × Gemini do artigo; remover o ramo `gemini` de
`make_model` e o extra `agno[google]` do `pyproject.toml` caso contrário. **Decisão do grupo.**

## 3. Substituir a identidade visual

**Por quê.** A marca Jev IDS é do orientador, desenhada no Figma dele. Um fork que a carrega se apresenta
como o projeto dele. Ou trocamos, ou tiramos e ficamos sem banner.

`docs/avatar.png`, `docs/avatar.svg`, `docs/banner.png`, `docs/banner.svg`, `docs/brand.md`,
`docs/request.svg`, `docs/verdict.svg` — cerca de 165 KB. As referências a eles estão no topo do
`README.md` da raiz.

**Manter:** `docs/results-f1.svg`, `docs/results-f1-three-sets.svg`, `docs/results-recall-precision.svg`.
São as figuras dos resultados publicados, nossa linha de base.

## 4. Enxugar `results/`

**Por quê.** São 75 MB de predições das execuções do orientador, 54 arquivos versionados. Não precisamos
delas para comparar: o que usamos é o resumo.

**Guardar sempre:** `results/paper/summary.csv`, `results/paper/compare-jev-gemini-{all,known,novel}.csv`,
e os `config.json` de `results/paper/`, que carregam os hashes de prompt, card e split que provam que
nossos números são comparáveis com os dele.

**Candidatos a sair:** os `predictions.jsonl` de `results/*/` fora de `results/paper/` (as execuções
`internal` e `pilot`, exploratórias).

## 5. Decidir sobre o NF-UQ-NIDS-v2

`data/nf-uq-nids-v2/dataset.json` e `scripts/prepare_nf_uq_nids_v2.py` descrevem um segundo conjunto de
dados que **nunca foi executado**, nem pelo orientador. As features NetFlow são mais realistas que as do
NSL-KDD e o `mutations.json` teria de ser refeito para ele.

Rodar o laço nele seria resultado inédito e forte para o artigo — e é trabalho de verdade, não limpeza.
**Manter e tratar como oportunidade**, não como pendência.

## 6. `make` não existe no Windows

O `Makefile` é o ponto de entrada documentado do projeto (`make check`, `make paper`), e a máquina de
desenvolvimento do grupo não tem `make`. Os comandos diretos estão em [`docs/arena/como-rodar.md`](como-rodar.md).

Alternativas: instalar `make` via Git Bash ou Chocolatey; ou escrever um `tasks.py` com o mesmo conteúdo.
Enquanto isso, os alvos do `Makefile` continuam válidos para o orientador, que usa macOS.

## 7. Mover a pesquisa para fora de `dev-docs/`

`dev-docs/` está no `.gitignore` herdado, então estes três arquivos **não estão versionados** e se perdem
se alguém clonar o repositório:

- `dev-docs/research-evasion-constraints.md` — o levantamento de literatura, com as citações verificadas
- `dev-docs/empirical-constraints-findings.md` — as medições sobre os 125.973 fluxos
- `dev-docs/research-agent-context-refs.md` — as referências de engenharia de contexto agêntica
- `dev-docs/arena-loop-design.md` — as decisões de protocolo

São a evidência por trás do `mutations.json` e do relatório, e o artigo vai precisar deles. Mover para
`docs/arena/` e versionar.
