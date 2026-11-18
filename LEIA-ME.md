# Central Operacional (Protemaxi) — Desenvolvido por Andrade

## Colocar no ar (≈10 minutos)

1. **Supabase** (grátis): crie um projeto novo → *SQL Editor* → cole todo o arquivo `supabase.sql` → **Run**.
2. Em *Project Settings → API*, copie a **Project URL** e a chave **anon / publishable**.
3. Abra `index.html`, procure `CONFIG` no topo e cole os dois valores em `supabaseUrl` e `supabaseKey`.
4. **GitHub**: crie um repositório novo, envie os 5 arquivos (`index.html`, `manifest.json`, `sw.js`, `icon.svg`, `supabase.sql`) e ative *Settings → Pages → main / root*.
5. Entre com **andrade / 1234** e troque o PIN em *Admin → Usuários*.
6. Em *Admin → Configurações*, clique em **Carregar carteira** (158 contas do Segware, ouros já marcados).

Sem o passo 3 o app funciona em **modo local** (os dados ficam só naquele navegador).

## Como funciona
- **Sem login**: qualquer pessoa vê o Painel (ideal para a TV — botão ⛶ TV).
- **Com login**: usuário + PIN. Quem não é admin só vê; você libera permissões por pessoa
  (OS, clientes, arquivos, coordenador). As regras ficam no banco, não só na tela.
- **Atraso**: número em cada OS = dias depois do prazo. Sem prazo, usa o prazo padrão
  (Admin → Configurações, começa em 3 dias após a abertura).
- **Importar Inside/Segware**: favorito "📥 Enviar para Central" (1 clique na tela aberta),
  print da tela (leitura automática do texto) ou copiar e colar. OS que saem da lista do Inside
  podem ser marcadas como concluídas automaticamente.
- **Relatórios** (Coordenador → Relatórios): escolha o cliente ou grupo, o período e o modelo → o app puxa as OS e monta o texto. Imprimir/PDF, copiar ou mandar no WhatsApp.
  Suba seus modelos (Word, PDF, texto ou print): o app troca nome do cliente, datas e responsável por campos automáticos.
- **Checklist**: tarefas com horário e dias da semana; avisa no celular/PC com o app aberto
  ou instalado (Chrome → Adicionar à tela inicial).
