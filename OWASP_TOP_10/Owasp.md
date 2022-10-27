OWASP TOP 10;
WSTG (Web Security Testing Guide)


Broken Authentication:

    Falhas mais comuns:

        Deixa fazer bruteforce;
        Weak credential (deixa cadastrar senhas fracas);
        Controle de timeout (continua logado mesmo depois de fechar o navegador e etc)

Sensitive Data Exposure:

    Falhas mais comuns:

        Transmite dados em clear text ou utiliza protocolos sem criptografia como HTTP, SMTP e FTP;

        Weak Cryptographic (utiliza criptografia fraca ou antiga);
        
        A solicitação do usuário utilizando algum cliente (browser, aplicativo e cliente de e-mail) não verifica se o certificado do servidor recebido é válido.

Broken Access Control:

    Falhas mais comuns:

        Bypass de ACL (Lista de controle de acesso) modificando a URL, o estado interno do aplicativo ou a página HTML ou simplesmente usando uma ferramenta de ataque de API personalizada (postman e etc);

        Pertir que a chave primeira (PK) seja alterada para o registro de usuário de outra pessoa, permitindo a visualização ou edição da conta de outra pessoa;

        Elevação de privilégio. Atuar como um usuário sem estar logado, ou agir como um administrador quando logado como um usuário comum;

        Manipualação de metadados, como reproduzir ou adulterar um token de controle de acesso JSON Web Token(JWT) ou um cookie ou campo oculto manipulado para elevar privilégios ou abusar da invalidação JWT (None algorithm attack)

        Falhas IDOR

Security Misconfiguration:

    Falhas mais comuns:

        Falta de proteção de segurança apropriada em qualquer parte da stack de aplicativo ou permissões configuradas incorretamente em serviços em nuvem (s3, elastic beanstalk, azure blobs e etc);

        Recursos desnecessários são ativados ou instalados (portas, serviços, páginas, contas ou privilégios desnecessários);

        Contas padrão e suas senhas ainda ativadas e inalteradas (ex: tomcat/tomcat);

        O tratamento de erros revela dados da stack ou outras mensagens de erro excessivamente informativas aos usuários;

        Modo debug ativado em Produção.

XSS (Cross site scripting)

    Falhas mais comuns:

        Reflected: O aplicativo ou API inclui entrada de usuário não validada e sem escape como parte da saída HTML, um ataque bem sucedido pode permitir que o invasor execute HTML e JS arbitrárias no navegador da vítima;

        Stored: O aplicativo ou API armazena entradas de usuários não sanitizadas que são visualizadas posteriormente por outro usuário ou administrador, esse tipo de vulnerabilidade é geralmente considerada de alto risco ou crítico;

        DOM XSS: Estruturas JS, aplicativos PWA e API's que incluem dinamicamente dados enviados por invasores em uma página, são vulneráveis a DOM XSS.

Insecure Deserialization:

    Falhas mais comuns:

        Ataques relacionados a objetos e estruturas de dados em que o atacante modifica a lógica do aplicativo ou atinge a execução remota de código se houver classes disponíveis para o aplicativo que podem alterar o comportamento durante ou após a desserialização;

        Ataques típicos de violação de dados, como ataques relacionados ao controle de acesso, em que as estruturas de dados existentes são usadas, mas o conteúdo é alterado (Algo como um BAC (Broken access control) porém usando desserialização insegura).

Using components with known vulnerabilities:

    Falhas mais comuns:

        Se você não souber as versões de todos os componentes que usa (tanto client quanto server);

        Se o software for vulnerável, sem suporte ou desatualizado. Isso inclui o sistema operacional, servidor web/aplicativo, sistema de gerenciamento de banco (DBMS), aplicativos, API's e todos os componentes, até mesmo as libs runtime;

        Se os desenvolvedores de software não testarem a compatibilidade de bibliotecas atualizadas ou com patches.

Insufficient Logging & Monitoring:

    Falhas mais comuns:

        Eventos auditáveis, como logins, logins com falha e transações "high-value não são registrados;

        Avisos e erros geram mensagens e log inadequadas ou pouco claras;

        Logs de aplicativos e API's não são monitorados para atividades suspeitas;

        Os logs são armazenados apenas localmente;

        O teste de penetração e varreduras por ferramentas DAST (como OWASP ZAP) não acionam alertas;

        O aplicativo não é capaz de detectar, escalar ou alertar para ataques ativos em tempo real ou quase real.