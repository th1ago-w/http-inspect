"""Inspeção educacional de cabeçalhos HTTP. Sem dependências externas."""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener


def validate_url(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('Informe uma URL completa com http:// ou https://.')
    if parts.username or parts.password:
        raise ValueError('URLs com usuário ou senha não são aceitas.')
    if parts.fragment:
        raise ValueError('Remova o fragmento (#...) da URL.')
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('A URL contém espaços ou caracteres de controle.')
    _ = parts.port
    return url


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        if urlsplit(req.full_url).scheme == 'https' and urlsplit(newurl).scheme != 'https':
            raise ValueError('Redirecionamento de HTTPS para HTTP recusado.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, timeout=10):
    request = Request(validate_url(url), headers={'User-Agent': 'HTTP-Inspect/1.0'}, method='GET')
    opener = build_opener(SafeRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        # Respostas 4xx/5xx também contêm cabeçalhos úteis.
        response = error
    with response:
        return response.geturl(), response.code, list(response.headers.items())


def analyze(url, status, headers):
    grouped = {}
    for name, value in headers:
        grouped.setdefault(name.lower(), []).append(value.strip())
    checks = []

    def add(name, state, explanation):
        checks.append(dict(header=name, status=state, value=' | '.join(grouped.get(name.lower(), [])), explanation=explanation))

    def value(name):
        return ', '.join(grouped.get(name.lower(), []))

    hsts = value('Strict-Transport-Security')
    ages = re.findall(r'(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)', hsts, re.I)
    if urlsplit(url).scheme != 'https':
        add('Strict-Transport-Security', 'atenção', 'A resposta final usa HTTP. HSTS só tem efeito quando recebido por HTTPS.')
    elif not hsts:
        add('Strict-Transport-Security', 'ausente', 'Não foi recebido HSTS para orientar o navegador a usar HTTPS nas próximas visitas.')
    elif len(ages) != 1 or len(grouped.get('strict-transport-security', [])) != 1 or int(ages[0]) == 0:
        add('Strict-Transport-Security', 'atenção', 'max-age inválido, duplicado ou zero; revise a configuração de HSTS.')
    else:
        add('Strict-Transport-Security', 'presente', f'max-age={ages[0]} segundos. A adequação do prazo depende do serviço.')

    csp = value('Content-Security-Policy')
    if csp:
        risky = any(token in csp.lower() for token in ("'unsafe-inline'", "'unsafe-eval'"))
        add('Content-Security-Policy', 'atenção' if risky else 'presente',
            'Política contém unsafe-inline ou unsafe-eval; revise no contexto das diretivas.' if risky else 'Política recebida. A presença não comprova que suas diretivas são adequadas.')
    else:
        report_only = bool(value('Content-Security-Policy-Report-Only'))
        add('Content-Security-Policy', 'ausente', 'Existe somente Report-Only: registra violações, sem bloquear.' if report_only else 'Não foi recebida uma política CSP de aplicação obrigatória.')

    nosniff = value('X-Content-Type-Options')
    add('X-Content-Type-Options', 'presente' if nosniff.lower() == 'nosniff' else ('atenção' if nosniff else 'ausente'),
        'Valor esperado: nosniff, para limitar a interpretação de tipos MIME pelo navegador.')

    frame = value('X-Frame-Options')
    if re.search(r'(?:^|[;,])\s*frame-ancestors\s+[^;,]+', csp, re.I):
        add('X-Frame-Options', 'informativo', 'CSP contém frame-ancestors, que pode controlar enquadramento. Revise os valores da diretiva.')
    else:
        add('X-Frame-Options', 'presente' if frame.upper() in ('DENY', 'SAMEORIGIN') else ('atenção' if frame else 'ausente'),
            'DENY ou SAMEORIGIN podem limitar enquadramento. A necessidade depende de como a página deve ser incorporada.')

    referrer = value('Referrer-Policy')
    policies = {'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'}
    recognized = [p.strip().lower() for p in referrer.split(',') if p.strip().lower() in policies]
    if not referrer:
        add('Referrer-Policy', 'ausente', 'Sem política explícita no cabeçalho; o navegador pode aplicar seu padrão ou uma política no HTML.')
    else:
        add('Referrer-Policy', 'presente' if recognized and recognized[-1] != 'unsafe-url' else 'atenção',
            'Política explícita reconhecida.' if recognized and recognized[-1] != 'unsafe-url' else 'Valor não reconhecido ou unsafe-url, que pode expor mais informações do endereço de origem.')

    permissions = value('Permissions-Policy')
    add('Permissions-Policy', 'presente' if permissions else 'ausente',
        'Permite restringir recursos como câmera e microfone. O conteúdo da política precisa de revisão manual.')
    return dict(url=url, http_status=status, checked_at=datetime.now(timezone.utc).isoformat(), checks=checks)


def display(report):
    print(f"HTTP Inspect\nURL final: {report['url']}\nHTTP: {report['http_status']}\n")
    for check in report['checks']:
        print(f"[{check['status'].upper()}] {check['header']}")
        if check['value']:
            print('  Valor: ' + check['value'])
        print('  ' + check['explanation'] + '\n')
    print('Análise heurística da resposta final. Não é uma auditoria nem uma garantia de segurança.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspeciona cabeçalhos HTTP de segurança de uma URL.')
    parser.add_argument('url', nargs='?', help='URL completa, incluindo https://')
    parser.add_argument('--demo', action='store_true', help='Usa dados fictícios sem conexão de rede.')
    parser.add_argument('--json', dest='output', help='Salva o relatório JSON no caminho informado.')
    parser.add_argument('--timeout', type=float, default=10, help='Timeout de operações de rede em segundos (padrão: 10).')
    args = parser.parse_args(argv)
    if args.demo == bool(args.url):
        parser.error('Informe uma URL ou use --demo, sem combinar os dois.')
    if not 0 < args.timeout <= 120:
        parser.error('--timeout precisa ser maior que zero e no máximo 120.')
    try:
        if args.demo:
            result = ('https://exemplo.test/', 200, [('Strict-Transport-Security', 'max-age=31536000'), ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'SAMEORIGIN'), ('Referrer-Policy', 'strict-origin-when-cross-origin')])
            print('DEMONSTRAÇÃO: dados fictícios; nenhuma consulta foi feita.\n')
        else:
            result = fetch(args.url, args.timeout)
        report = analyze(*result)
        report['demo'] = args.demo
        display(report)
        if args.output:
            with open(args.output, 'x', encoding='utf-8') as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
            print(f'Relatório salvo: {args.output}')
        return 0
    except (ValueError, OSError, URLError) as error:
        print(f'Erro: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
