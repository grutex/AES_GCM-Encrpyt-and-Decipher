# AES_GCM-Cypher-and-Decypher
2 Separate algorithms that Cyphers &amp; Decyphers any given Plain Text with the given key using AES-GCM


RABC Programa de cifra simétrica de bloco AES-GCM.

[PT-BR]


Para Encriptar uma messagem:
--------------------
Plain Text e Key estão pre-setados no programa, mas podem ser alterados.

1 - crie um executável do código usando GCC ou qualquer outro compilador, passando -lssl e -lcrypto.
	ex.: gcc < programa.c > -o < nome_do_executavel > -lssl -lcrypto

2 - execute-o no terminal, um print com o exto cifrado, iv e a tag serão gerados baseados no plain_text
	e na chave.

3 - parâmetros criptografados, já em hexadecimal, serão gerados e imprimidos no terminal.



Para Decifrar a menssagem:
-----------------------
1 - crie um executável do código usando GCC ou qualquer outro compilador, passando -lssl e -lcrypto.
	ex.: gcc < programa.c > -o < nome_do_executavel > -lssl -lcrypto

2 - passe na linha de comando o texto cifrado, o vetor de inicialização(iv) e a tag do GCM (em HEXADECIMAL)
	exatamente nessa ordem (argv[1], [2], [3]) valores que são dados após a execução do código.
	ex.: ./decrypt < hex_plaintext > <hex_iv> <hex_tagGCM>
		
3 - Se os parâmetros derem match, a me


[EN-US]


To Encrypt a message:
--------------------
1 — Create an executable from the code using GCC or any other compiler, passing the -lssl and -lcrypto flags.

Example: gcc <program.c> -o <executable_name> -lssl -lcrypto

2 — Run it in the terminal. A printout containing the ciphertext, IV (Initialization Vector), and tag will be generated based on the plain_text and the key.

3 — Encrypted parameters, already in hexadecimal format, will be generated and printed to the terminal.

Aqui está a continuação da tradução, mantendo o tom técnico e o padrão de documentação:


To Decrypt the Message:
--------------------
1 — Create an executable from the code using GCC or any other compiler, passing the -lssl and -lcrypto flags.

Example: gcc <program.c> -o <executable_name> -lssl -lcrypto

2 — Pass the ciphertext, Initialization Vector (IV), and the GCM tag (in HEXADECIMAL) via command line, exactly in that order (argv[1], [2], [3]). These are the values provided after executing the encryption code.

Example: ./decrypt <hex_ciphertext> <hex_iv> <hex_tagGCM>

3 — If the parameters match, the original message will be decrypted and displayed.
