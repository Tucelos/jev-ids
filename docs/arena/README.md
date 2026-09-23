# `docs/arena/` — a documentação do laço adversarial

Esta pasta é tudo o que o fork escreveu sobre a Arena: os dois guias de estudo do grupo, em português,
e os quatro documentos de pesquisa que sustentam as decisões de projeto, em inglês, como o código e as
docstrings. Os documentos de pesquisa não são rascunhos — são a evidência por trás do
`data/nsl-kdd/mutations.json`, do relatório da disciplina e de qualquer artigo futuro, e nenhum número
deles foi reescrito para caber numa história. Se um documento e o código discordarem, o código é o que
roda e [`loop-design.md`](loop-design.md) é o que o código promete fazer.

| Documento | Idioma | A pergunta que responde |
|---|---|---|
| [`como-rodar.md`](como-rodar.md) | Português | Nunca abri este projeto. Como coloco uma Round rodando, e como leio o que ela escreveu? |
| [`arquitetura.md`](arquitetura.md) | Português | O que cada peça faz e, sobretudo, **por que é assim**? O guia de estudo para a prova oral. |
| [`loop-design.md`](loop-design.md) | Inglês | Qual é o protocolo? O que é uma Round, quais são os três Splits, quanto custa, quais são os braços de ameaça e quais linhas de base o resultado exige. **A autoridade sobre o que o sistema faz.** |
| [`empirical-constraints.md`](empirical-constraints.md) | Inglês | O que os 125.973 Flows do Pool realmente dizem? As identidades de acoplamento medidas, os limites dos dois levers diretos, a assinatura r2l, e o que continua cientificamente fraco. |
| [`evasion-constraints.md`](evasion-constraints.md) | Inglês | O que a literatura já estabeleceu sobre perturbação realista de fluxos? Pierazzi, Apruzzese, IDSGAN, Sheatsley, e por que as 19 features derivadas não podem ser escritas pelo atacante. |
| [`agent-context-refs.md`](agent-context-refs.md) | Inglês | Quais são as referências verificadas de engenharia de contexto agêntica e da sua segurança? ACE, AgentPoison, OWASP LLM Top 10, MITRE ATLAS. |
| [`tarefas.md`](tarefas.md) | Português | O que herdamos do repositório do orientador e ainda não decidimos? Sete pendências com os arquivos exatos. **Nada aqui é urgente.** |

## Fora desta pasta

- [`trabalho-adversarial/README.md`](../../trabalho-adversarial/README.md) — **o relatório da
  disciplina**, em português: atores, ativo a preservar, modelo estratégico estático e dinâmico,
  ameaças e riscos, limitações. É o documento que o grupo entrega e defende; esta pasta é o material
  de apoio dele.
- [`../../README.md`](../../README.md) — a página inicial do fork, em inglês, com os comandos.
- [`../../CONTEXT.md`](../../CONTEXT.md) — o glossário. Flow, Category, Split, Detector, Prediction,
  Verdict. Os termos técnicos em inglês no texto em português desta pasta seguem esse arquivo.
- [`../upstream-readme.md`](../upstream-readme.md), [`../protocol.md`](../protocol.md) e
  [`../results.md`](../results.md) — o projeto base: a página inicial do orientador, o protocolo do
  artigo dele e os resultados publicados. Nossa linha de base, e não nossos números.

## Uma ordem de leitura

Para quem vai defender o trabalho: [`arquitetura.md`](arquitetura.md) primeiro, porque explica o
*porquê* de cada decisão; [`loop-design.md`](loop-design.md) em seguida, para o protocolo exato; e
[`empirical-constraints.md`](empirical-constraints.md) §1 e §4 por último, porque é de lá que sai a
resposta para a pergunta que um examinador certamente fará — *por que o atacante copia um bloco de
features em vez de calculá-lo*.

Para quem só precisa rodar: [`como-rodar.md`](como-rodar.md), e nada mais.
