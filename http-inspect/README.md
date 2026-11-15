# HTTP Inspect

Ferramenta de terminal em Python para consultar uma URL e explicar os cabeçalhos HTTP de segurança da resposta final. Projeto educacional desenvolvido com auxílio de IA, usando apenas a biblioteca padrão.

## Executar

Requer Python 3.10 ou superior. Extraia os arquivos e abra um terminal na pasta do projeto.

```bash
python http_inspect.py --demo
```

A demonstração usa dados fictícios e funciona sem internet. Para consultar uma URL real:

```bash
python http_inspect.py https://example.com
python http_inspect.py https://example.com --json relatorio.json
python http_inspect.py https://example.com --timeout 15
```

No Windows, você pode usar `py` no lugar de `python`. Não precisa instalar pacotes.

## O que analisa

| Cabeçalho | Verificação |
| --- | --- |
| Strict-Transport-Security | HTTPS, presença e max-age positivo |
| Content-Security-Policy | Presença e indícios de unsafe-inline/unsafe-eval |
| X-Content-Type-Options | Valor nosniff |
| X-Frame-Options | DENY/SAMEORIGIN, considerando a presença de frame-ancestors na CSP |
| Referrer-Policy | Valores reconhecidos e alerta para unsafe-url |
| Permissions-Policy | Presença; revisão manual do conteúdo |

Os resultados usam `presente`, `ausente`, `atenção` ou `informativo`. **Presente não significa configuração segura**, e ausente não comprova vulnerabilidade. Não há nota de segurança porque a interpretação depende do tipo de aplicação e da resposta.

Exemplo parcial do modo de demonstração:

```text
HTTP Inspect
URL final: https://exemplo.test/
HTTP: 200

[PRESENTE] X-Content-Type-Options
  Valor: nosniff

[AUSENTE] Content-Security-Policy
```

A saída real inclui explicações e os seis cabeçalhos. O relatório JSON inclui URL final, status HTTP, horário UTC e resultados. Um arquivo existente não é sobrescrito: escolha outro nome para exportar novamente.

## Como funciona

Faz uma requisição GET com User-Agent `HTTP-Inspect/1.0`, segue redirecionamentos HTTP/HTTPS e fecha a resposta sem carregar seu corpo. Mantém a validação TLS padrão e recusa redirecionamentos de HTTPS para HTTP. Respostas 4xx/5xx também são analisadas. O timeout é de operações de rede, não um limite global para toda a cadeia de redirecionamentos.

O código de saída é 0 para uma análise concluída e 2 para erros. Cabeçalhos ausentes não mudam o código de saída.

## Testes

```bash
python -m unittest -v
```

Os testes incluem normalização de nomes, HSTS desativado/duplicado, CSP Report-Only, frame-ancestors, URLs inválidas, exportação e um servidor HTTP local com redirecionamento e resposta 404.

## Limitações

- Inspeciona apenas a resposta final da URL informada, sem rastrear outras páginas.
- Não executa JavaScript nem lê políticas definidas em tags HTML.
- A análise de CSP é heurística, não um parser completo de suas diretivas. Tokens sinalizados podem ter efeitos diferentes conforme o contexto.
- Não analisa cookies nem garante a validade completa das políticas recebidas.
- APIs, imagens e páginas HTML têm necessidades diferentes. Revise cada resultado no contexto.
- A requisição é enviada diretamente ao endereço escolhido, que pode registrar o acesso. Não há serviço externo de análise.
- URLs e valores dos cabeçalhos aparecem no terminal e no relatório; evite publicar relatórios com informações privadas.

## Estrutura

```text
http_inspect.py        CLI, consulta HTTP e regras
test_http_inspect.py   Testes automatizados
README.md             Instruções e limitações
```

## Referências

- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options)
- [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)

## Ideias para evoluir

- Exibir a cadeia de redirecionamentos.
- Adicionar testes para políticas mais complexas.
- Oferecer saída em Markdown para revisão manual.

Nome sugerido do repositório: `http-inspect`.

Descrição: `Ferramenta em Python para inspecionar cabeçalhos HTTP de segurança, explicar configurações e exportar relatórios JSON.`
