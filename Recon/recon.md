Intelligence gathering:

    Subdomain discovery:
        A ideia nesta etapa é obter o máximo de subdomínios de um domínio raíz/principal.

    Application discovery:
        O objetivo nessa etapa é obter informações sobre as aplicações que estão rodando nos subdomínios, utilizamos prints de sites e informações como URL's e parâmetros das aplicações.

    Web fuzzing:
        O objetivo nessa etapa é obter informações sobre quais arquivos, rotas e pastas existem dentro de uma aplicação web e/ou endpoint de API.

    Automation:
        Podemos utilizar algumas automações para nos ajudar a deixar este trabalho mais rápido e efetivo.


    Subdomain discovery:
        Histórico de subdomain:
            securitytrails.com;
            subdomainfinder.c99.nl;
            web.archive.org;
            dnsdumpster.com;
            github.com/Screetsec/Sudomy;

        Brute force:
            Sublist3r;
            subbrute;
            Amass;

        Certificados e passivos:
            subfinder;
            certspotter;
            github.com/UnaPibaGeek/ctfr;
            chaos.projectdiscovery.io;

Subdomain Discovery:

    Ferramenta mais eficaz na minha visão:

    subfinder -d site.com -o sitedomains.txt

    Faz enumeração de subdomains de forma agil.

    chaos.projectdiscovery.io traz listas prontas de subdomain de programas de bugbounty


Application discovery:

    Renomeei meu gau para geturls devido ao oh my zsh

    A utilização do gau(geturls) é da seguinte maneira:

    echo "renanzapelini.com.br" | geturls

    Passamos a url por pipe para o programa, e ele vai achar as urls para a gente.

    Vamos fazer uma enumeração de subdomain:

    subfinder -d renanzapelini.com.br -o arquivo.txt

    E vamos testar para ver quais desses subdomains possuem aplicações web com httpx:

    cat arquivo.txt | httpx -status-code

    O comando acima  mostra as requisições com status-code

    Para testar um path nos endereços no arquivo.txt podemos declarar um -path da seguinte maneira:

    cat arquivo.txt | httpx -status-code -path /admin

    Podemos utilizar o -silent para exibir apenas as que existem:

    cat arquivo.txt | httpx -silent

    E melhorando ainda mais a busca de informações podemos utilizar o gau (geturls no nosso caso) para buscar urls naqueles subdomínios da seguinte maneira:

    cat arquivo.txt | httpx -silent | geturls

    Exemplo de comando completo pra enumerar urls de subdomínios:

    subfinder -d renanzapelini.com.br -silent | httpx -silent | geturls


Parameter discovery:

    Utilizando paramspider podemos identificar parâmetros da seguinte maneira:

    ./paramspider.py -d nubank.com.br

    Os parâmetros vão retornar como FUZZ, para verificar se o parâmetro é reflected ou não.

    Para testar se os parâmetros são refletidos ou não podemos utilizar outra ferramenta, que é o kxss

    o comando seria o seguinte:

    ./paramspider.py -d nubank.com.br | kxss


Fuzzing de pasta e arquivos:

    Fazer fuzzing de pasta e arquivo conforme wordlist:

        wfuzz -c -z file,directory-list-2.3-big.txt http://10.9.2.10/FUZZ

    Porém esse comando irá trazer muitos 404, como podemos ignorar essas respostas? Podemos fazer da seguinte maneira:

        wfuzz -c -z file,directory-list-2.3-big.txt --hc 404 http://10.9.2.10/FUZZ

    Para mostrar um status-code específico utilizamos o --sc, assim:

        wfuzz -c -z file,directory-list-2.3-big.txt --sc 200 http://10.9.2.10/FUZZ  

    Como podemos aumentar a velocidade da ferramenta? Usando threads é óbvio, hehe, o comando fica da seguinte maneira:

        wfuzz -t 100 -c -z file,directory-list-2.3-big.txt --hc 404 http://10.9.2.10/FUZZ


Fuzzing de parâmetros com wfuzz:

    O comando ficaria da seguinte maneira:

        wfuzz -c -z file,burp-parameter-names.txt http://10.9.2.10/index.php?FUZZ=teste

    porém, ele pode retornar apenas status-code 200, então precisaremos filtrar por o tanto de chars/linhas, as páginas de status-code 200 retornam 2042 caracteres, porém não queremos que apareçam no fuzzing, vamos filtrar com o parâmetro --hh 2042 da seguinte maneira:

        wfuzz -c -z file,burp-parameter-names.txt --hh 2042 http://10.9.2.10/index.php?FUZZ=teste


    