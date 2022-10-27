LFI é utilizado normalmente para efetuar a leitura de arquivos locais do servidor, um exemplo de código vulnerável seria o seguinte:

```php
<?php
    $value = $_GET['page'];
    $conteudo_do_arquivo = file_get_contents($value);
    echo $conteudo_do_arquivo;
?>
```

Ok, mas quem vai querer ler o arquivo do servidor assim? Aí que mora o pulo do miau, imagine que em uma página a navegação é feita por um parâmetro chamado `page`, e a página é buscada a partir dele da seguinte maneira:


```php
<?php
    if(isset($_GET['page']) AND !empty($_GET['page'])) {
        echo file_get_contents($_GET['page']);
    } else {
        echo file_get_contents("pages/home.html");
    }
?>
```

A exploração se da ao valor passado ao parâmetro `page`, exemplo:

`https://site.com.br?page=index.html`

Esse no caso é um valor válido, porque no diretório que está buscando existe o index.html, porém podemos colocar um valor malicioso para buscar o arquivo `/etc/passwd` no servidor da seguinte maneira:

`https://site.com.br?page=../../../../../../../../etc/passwd`

Nossa, pra que voltar tantos diretórios? Porque não sabemos quantos diretórios acima está a raíz do sistema, por isso precisamos utilizar directory transversal também.