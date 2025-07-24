from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from PIL import Image
import re
import os
import uuid
import smtplib
import json
import sqlite3

app = Flask(__name__)
app.secret_key = "@Darel230109"

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = 'adrelwilion@gmail.com'  
EMAIL_PASS = '@Darel230109'     
EMAIL_DESTINO = 'adrelwilion@gmail.com'

# ========== FUNÇÕES UTILITÁRIAS ==========

def validar_email(email):
    """Valida formato de email usando regex"""
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def allowed_file(filename):
    """Verifica se o arquivo possui extensão permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def processar_imagem(arquivo):
    """Salva e redimensiona imagem otimizando para web"""
    if not arquivo or not allowed_file(arquivo.filename):
        return None
    
    filename = secure_filename(arquivo.filename)
    nome_base, ext = os.path.splitext(filename)
    nome_unico = f"{nome_base}_{uuid.uuid4().hex[:8]}{ext}"
    caminho = os.path.join(UPLOAD_FOLDER, nome_unico)
    
    try:
        arquivo.save(caminho)
        with Image.open(caminho) as img:
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            img.thumbnail((800, 800), Image.Resampling.LANCZOS)
            img.save(caminho, 'JPEG', quality=85, optimize=True)
        return nome_unico
    except Exception as e:
        print(f"Erro ao processar imagem: {e}")
        if os.path.exists(caminho):
            os.remove(caminho)
        return None

def remover_imagem(nome_arquivo):
    """Remove arquivo de imagem do sistema"""
    if nome_arquivo:
        caminho = os.path.join(UPLOAD_FOLDER, nome_arquivo)
        try:
            if os.path.exists(caminho):
                os.remove(caminho)
        except Exception as e:
            print(f"Erro ao remover imagem: {e}")

def get_db():
    """Retorna conexão com banco SQLite com row_factory configurado"""
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_id(nome_usuario):
    """Retorna o ID do usuário pelo nome"""
    with get_db() as conn:
        user = conn.execute('SELECT id FROM usuarios WHERE nome = ?', (nome_usuario,)).fetchone()
        return user['id'] if user else None

def is_admin():
    """Verifica se o usuário atual é administrador"""
    return session.get('usuario') == 'admin'

def get_admin_projects():
    """Retorna projetos do admin para exibição no calendário"""
    admin_id = get_user_id('admin')
    if not admin_id:
        return []
    
    with get_db() as conn:
        return conn.execute('SELECT * FROM eventos_calendario WHERE usuario_id = ? ORDER BY data_inicio ASC', 
                           (admin_id,)).fetchall()
def enviar_email_pedido(dados_pedido):
    """Envia email com detalhes do pedido"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_DESTINO
        msg['Subject'] = f"Novo Pedido - #{dados_pedido['id']}"
        
        corpo = f"""
        NOVO PEDIDO RECEBIDO
        
        Pedido: #{dados_pedido['id']}
        Cliente: {dados_pedido['cliente']}
        Email: {dados_pedido['email']}
        
        ENDEREÇO DE ENTREGA:
        {dados_pedido['endereco']}
        
        ITENS DO PEDIDO:
        {dados_pedido['itens']}
        
        TOTAL: R$ {dados_pedido['total']}
        Data: {dados_pedido['data']}
        """
        
        msg.attach(MIMEText(corpo, 'plain'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except:
        return False

# ========== DECORADORES ==========

def login_required(f):
    """Decorador que exige login para acessar rota"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorador que exige privilégios de admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            return redirect('/index')
        return f(*args, **kwargs)
    return decorated

# ========== INICIALIZAÇÃO DO BANCO DE DADOS ==========

def init_db():
    """Inicializa banco de dados com tabelas e dados padrão"""
    with sqlite3.connect('app.db') as conn:
        cursor = conn.cursor()
        
        # Criação das tabelas
        cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            senha_original TEXT)''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS noticias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            conteudo TEXT NOT NULL,
            data_publicacao TEXT,
            autor TEXT)''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS plantas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            tipo TEXT NOT NULL,
            descricao TEXT,
            data_plantio TEXT,
            observacoes TEXT,
            usuario_id INTEGER NOT NULL,
            data_criacao TEXT,
            imagem TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id))''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS eventos_calendario (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descricao TEXT,
            data_inicio TEXT NOT NULL,
            data_fim TEXT,
            cor TEXT DEFAULT '#28a745',
            usuario_id INTEGER NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            preco REAL NOT NULL,
            categoria TEXT NOT NULL,
            descricao TEXT,
            imagem TEXT,
            estoque INTEGER DEFAULT 0,
            ativo BOOLEAN DEFAULT 1,
            data_criacao TEXT)''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pendente',
            data_pedido TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id))''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS itens_pedido (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pedido_id INTEGER NOT NULL,
            produto_id INTEGER NOT NULL,
            quantidade INTEGER NOT NULL,
            preco_unitario REAL NOT NULL,
            FOREIGN KEY (pedido_id) REFERENCES pedidos (id),
            FOREIGN KEY (produto_id) REFERENCES produtos (id))''')
        
        # Função para adicionar colunas se não existirem
        def add_column_if_not_exists(table, column, definition):
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]
            if column not in columns:
                cursor.execute(f'ALTER TABLE {table} ADD COLUMN {definition}')
        
        # Adicionar colunas que podem estar faltando
        add_column_if_not_exists('usuarios', 'senha_original', 'senha_original TEXT')
        add_column_if_not_exists('usuarios', 'email', 'email TEXT')
        add_column_if_not_exists('noticias', 'data_publicacao', 'data_publicacao TEXT')
        add_column_if_not_exists('plantas', 'imagem', 'imagem TEXT')
        add_column_if_not_exists('pedidos', 'endereco', 'endereco TEXT')
        
        # Inserir usuários padrão se não existirem
        cursor.execute('SELECT COUNT(*) FROM usuarios')
        if cursor.fetchone()[0] == 0:
            users = [
                ('admin', 'admin@sementediaria.com', 'senha2301'),
                ('darelskidrop', 'darel@sementediaria.com', 'livros2025')
            ]
            for nome, email, senha in users:
                cursor.execute('INSERT INTO usuarios (nome, email, senha, senha_original) VALUES (?, ?, ?, ?)',
                             (nome, email, generate_password_hash(senha), senha))
        
        # Inserir produtos padrão se não existirem
        cursor.execute('SELECT COUNT(*) FROM produtos')
        if cursor.fetchone()[0] == 0:
            produtos_padrao = [
                ('Sementes de Tomate', 15.99, 'sementes', 'Sementes orgânicas de tomate cereja', '🍅', 50),
                ('Pá de Jardinagem', 35.50, 'ferramentas', 'Pá resistente para jardinagem', '🪚', 25),
                ('Fertilizante Orgânico', 28.00, 'fertilizantes', 'Fertilizante 100% orgânico 2kg', '🌱', 30),
                ('Vaso de Cerâmica', 45.90, 'vasos', 'Vaso decorativo de cerâmica 30cm', '🏺', 15),
                ('Sementes de Alface', 12.50, 'sementes', 'Sementes de alface crespa', '🥬', 40),
                ('Regador 5L', 89.90, 'ferramentas', 'Regador plástico resistente', '💧', 20),
                ('Sementes de Cenoura', 18.75, 'sementes', 'Sementes híbridas de cenoura', '🥕', 35),
                ('Tesoura de Poda', 67.50, 'ferramentas', 'Tesoura profissional para poda', '✂️', 12),
                ('Adubo Líquido', 24.90, 'fertilizantes', 'Adubo líquido concentrado 500ml', '🧪', 22),
                ('Vaso Plástico Grande', 29.99, 'vasos', 'Vaso plástico resistente 40cm', '🪴', 18)
            ]
            
            for nome, preco, categoria, descricao, imagem, estoque in produtos_padrao:
                cursor.execute('''INSERT INTO produtos (nome, preco, categoria, descricao, imagem, estoque, data_criacao)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
                              (nome, preco, categoria, descricao, imagem, estoque,
                               datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

# ========== ROTAS PRINCIPAIS ==========

@app.route('/')
def home():
    """Rota inicial - redireciona conforme estado de login"""
    return redirect('/index' if 'usuario' in session else '/login')

@app.route('/index')
@login_required
def index():
    """Página inicial do sistema"""
    return render_template('index.html', usuario=session['usuario'])

@app.route('/redes')
def redes():
    """Página de redes sociais"""
    return render_template('redes.html')

@app.route('/ajuda')
def ajuda():
    """Página de ajuda"""
    return render_template('ajuda.html')

@app.route('/servicos')
def servicos():
    """Página de serviços - redireciona para loja"""
    return render_template('loja.html')

# ========== AUTENTICAÇÃO ==========

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Sistema de login com email ou nome de usuário"""
    if request.method == 'POST':
        login_input = request.form['login_input'].strip()
        senha = request.form['senha']
        
        if not login_input or not senha:
            return render_template('login.html', erro='Preencha todos os campos.')
        
        with get_db() as conn:
            campo = 'email' if '@' in login_input else 'nome'
            user = conn.execute(f'SELECT * FROM usuarios WHERE {campo} = ?', (login_input,)).fetchone()
            
            if not user:
                return render_template('login.html', erro='❌ Usuário não encontrado!')
            
            if not check_password_hash(user['senha'], senha):
                return render_template('login.html', erro='❌ Senha incorreta!')
            
            session['usuario'] = user['nome']
            return redirect('/index')
    
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    """Sistema de cadastro de novos usuários"""
    if request.method == 'POST':
        nome, email, senha = request.form['nome'].strip(), request.form['email'].strip(), request.form['senha']
        
        if not all([nome, email, senha]):
            return render_template('cadastro.html', erro='Todos os campos são obrigatórios.')
        
        if not validar_email(email):
            return render_template('cadastro.html', erro='Email inválido!')
        
        if len(senha) < 6:
            return render_template('cadastro.html', erro='Senha deve ter 6+ caracteres.')
        
        with get_db() as conn:
            if conn.execute('SELECT 1 FROM usuarios WHERE nome = ?', (nome,)).fetchone():
                return render_template('cadastro.html', erro='Nome já existe!')
            
            if conn.execute('SELECT 1 FROM usuarios WHERE email = ?', (email,)).fetchone():
                return render_template('cadastro.html', erro='Email já cadastrado!')
            
            conn.execute('INSERT INTO usuarios (nome, email, senha, senha_original) VALUES (?, ?, ?, ?)', 
                        (nome, email, generate_password_hash(senha), senha))
            session['usuario'] = nome
            return redirect('/index')
    
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    """Sistema de logout"""
    session.pop('usuario', None)
    return redirect('/login')

# ========== GERENCIAMENTO DE PLANTAS ==========

@app.route('/plantas')
@login_required
def plantas():
    """Página de listagem de plantas do usuário"""
    usuario_id = get_user_id(session['usuario'])
    if not usuario_id:
        flash('Usuário não encontrado!', 'error')
        return redirect('/index')
    
    with get_db() as conn:
        plantas = conn.execute('SELECT * FROM plantas WHERE usuario_id = ? ORDER BY data_criacao DESC', 
                              (usuario_id,)).fetchall()
    
    return render_template('plantas.html.j2', plantas=plantas)

@app.route('/adicionar_planta', methods=['POST'])
@login_required
def adicionar_planta():
    """Adiciona nova planta ao sistema"""
    nome, tipo = request.form.get('nome', '').strip(), request.form.get('tipo', '').strip()
    
    if not nome or not tipo:
        flash('Nome e tipo são obrigatórios!', 'error')
        return redirect('/plantas')
    
    usuario_id = get_user_id(session['usuario'])
    if not usuario_id:
        flash('Usuário não encontrado!', 'error')
        return redirect('/plantas')
    
    # Processamento de imagem
    arquivo = request.files.get('imagem')
    if arquivo and arquivo.filename:
        arquivo.seek(0, os.SEEK_END)
        if arquivo.tell() > MAX_FILE_SIZE:
            flash('Arquivo muito grande! Máximo: 5MB', 'error')
            return redirect('/plantas')
        arquivo.seek(0)
    
    imagem_nome = processar_imagem(arquivo) if arquivo and arquivo.filename else None
    
    with get_db() as conn:
        conn.execute('''INSERT INTO plantas (nome, tipo, descricao, data_plantio, observacoes, 
                       usuario_id, data_criacao, imagem) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (nome, tipo, request.form.get('descricao', ''), request.form.get('data_plantio', ''),
                     request.form.get('observacoes', ''), usuario_id, 
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'), imagem_nome))
    
    flash('Planta adicionada!', 'success')
    return redirect('/plantas')

@app.route('/editar_planta/<int:planta_id>', methods=['POST'])
@login_required
def editar_planta(planta_id):
    """Edita informações de uma planta existente"""
    usuario_id = get_user_id(session['usuario'])
    nome, tipo = request.form.get('nome', '').strip(), request.form.get('tipo', '').strip()
    
    if not nome or not tipo:
        flash('Nome e tipo são obrigatórios!', 'error')
        return redirect('/plantas')
    
    with get_db() as conn:
        planta = conn.execute('SELECT * FROM plantas WHERE id = ? AND usuario_id = ?', 
                            (planta_id, usuario_id)).fetchone()
        
        if not planta:
            flash('Planta não encontrada!', 'error')
            return redirect('/plantas')
        
        imagem_nome = planta['imagem']
        arquivo = request.files.get('imagem')
        
        if arquivo and arquivo.filename:
            arquivo.seek(0, os.SEEK_END)
            if arquivo.tell() > MAX_FILE_SIZE:
                flash('Arquivo muito grande!', 'error')
                return redirect('/plantas')
            arquivo.seek(0)
            
            nova_imagem = processar_imagem(arquivo)
            if nova_imagem:
                if imagem_nome:
                    remover_imagem(imagem_nome)
                imagem_nome = nova_imagem
        
        conn.execute('''UPDATE plantas SET nome=?, tipo=?, descricao=?, data_plantio=?, 
                       observacoes=?, imagem=? WHERE id=? AND usuario_id=?''',
                    (nome, tipo, request.form.get('descricao', ''), request.form.get('data_plantio', ''),
                     request.form.get('observacoes', ''), imagem_nome, planta_id, usuario_id))
    
    flash('Planta atualizada!', 'success')
    return redirect('/plantas')

@app.route('/excluir_planta/<int:planta_id>', methods=['POST'])
@login_required
def excluir_planta(planta_id):
    """Exclui uma planta do sistema"""
    usuario_id = get_user_id(session['usuario'])
    
    with get_db() as conn:
        planta = conn.execute('SELECT * FROM plantas WHERE id = ? AND usuario_id = ?', 
                            (planta_id, usuario_id)).fetchone()
        
        if not planta:
            flash('Planta não encontrada!', 'error')
            return redirect('/plantas')
        
        if planta['imagem']:
            remover_imagem(planta['imagem'])
        
        conn.execute('DELETE FROM plantas WHERE id = ? AND usuario_id = ?', (planta_id, usuario_id))
    
    flash('Planta excluída!', 'success')
    return redirect('/plantas')

# ========== SISTEMA DE NOTÍCIAS (CAMPUS) ==========

@app.route('/campus', methods=['GET', 'POST'])
@login_required
def campus():
    """Sistema de gerenciamento de notícias do campus"""
    if request.method == 'POST' and is_admin():
        titulo, conteudo = request.form['titulo'].strip(), request.form['conteudo'].strip()
        id_noticia = request.form.get('id_noticia')
        
        if titulo and conteudo:
            with get_db() as conn:
                if id_noticia:
                    conn.execute('UPDATE noticias SET titulo=?, conteudo=?, data_publicacao=?, autor=? WHERE id=?',
                                (titulo, conteudo, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                                 session['usuario'], id_noticia))
                    flash('Notícia atualizada!', 'success')
                else:
                    conn.execute('INSERT INTO noticias (titulo, conteudo, data_publicacao, autor) VALUES (?, ?, ?, ?)',
                                (titulo, conteudo, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['usuario']))
                    flash('Notícia adicionada!', 'success')
        else:
            flash('Preencha todos os campos!', 'error')
    
    with get_db() as conn:
        noticias = conn.execute('SELECT * FROM noticias ORDER BY data_publicacao DESC').fetchall()
    
    return render_template('campus.html.j2', noticias=noticias)

@app.route('/excluir_noticia/<int:id>', methods=['POST'])
@login_required
@admin_required
def excluir_noticia(id):
    """Exclui uma notícia do sistema"""
    with get_db() as conn:
        if conn.execute('SELECT 1 FROM noticias WHERE id = ?', (id,)).fetchone():
            conn.execute('DELETE FROM noticias WHERE id = ?', (id,))
            flash('Notícia excluída!', 'success')
        else:
            flash('Notícia não encontrada!', 'error')
    
    return redirect('/campus')

# ========== GERENCIAMENTO DE USUÁRIOS ==========

@app.route('/usuarios')
@login_required
def listar_usuarios():
    """Lista todos os usuários do sistema"""
    with get_db() as conn:
        usuarios = conn.execute('SELECT nome, email, senha, senha_original FROM usuarios ORDER BY nome').fetchall()
    
    usuarios_list = [{
        'nome': u['nome'],
        'email': u['email'] or 'N/A',
        'senha_hash': u['senha'],
        'senha_original': u['senha_original'] or 'N/A'
    } for u in usuarios]
    
    return render_template('usuarios.html', usuarios=usuarios_list)

@app.route('/excluir_usuario/<nome_usuario>', methods=['POST'])
@login_required
@admin_required
def excluir_usuario(nome_usuario):
    """Exclui um usuário e todos os seus dados"""
    if session['usuario'] == nome_usuario:
        flash('Não pode excluir seu próprio usuário!', 'error')
        return redirect('/usuarios')
    
    usuario_id = get_user_id(nome_usuario)
    if not usuario_id:
        flash('Usuário não encontrado!', 'error')
        return redirect('/usuarios')
    
    with get_db() as conn:
        # Remove imagens das plantas do usuário
        plantas = conn.execute('SELECT imagem FROM plantas WHERE usuario_id = ?', (usuario_id,)).fetchall()
        for planta in plantas:
            if planta['imagem']:
                remover_imagem(planta['imagem'])
        
        # Remove dados do usuário
        conn.execute('DELETE FROM plantas WHERE usuario_id = ?', (usuario_id,))
        conn.execute('DELETE FROM usuarios WHERE nome = ?', (nome_usuario,))
    
    flash(f'Usuário "{nome_usuario}" excluído!', 'success')
    return redirect('/usuarios')

# ========== SISTEMA DE PROJETOS/CALENDÁRIO ==========

@app.route('/calendario')
@login_required
def calendario():
    """Página do calendário de projetos"""
    projetos = [dict(p) for p in get_admin_projects()]
    return render_template('calendario.html.j2', projetos=projetos)

@app.route('/projetos')
@login_required
def projetos():
    """Página de visualização de projetos com status"""
    projetos_raw = get_admin_projects()
    projetos = []
    data_atual = datetime.now()
    
    for p in projetos_raw:
        projeto = dict(p)
        try:
            data_inicio = datetime.strptime(projeto['data_inicio'], '%Y-%m-%d')
            data_fim = datetime.strptime(projeto['data_fim'], '%Y-%m-%d') if projeto['data_fim'] else None
            
            if data_fim and data_atual > data_fim:
                projeto.update({'status': 'concluido', 'status_texto': 'Concluído'})
            elif data_atual >= data_inicio:
                projeto.update({'status': 'em-andamento', 'status_texto': 'Em Andamento'})
            else:
                projeto.update({'status': 'aguardando', 'status_texto': 'Aguardando'})
        except ValueError:
            projeto.update({'status': 'aguardando', 'status_texto': 'Aguardando'})
        
        projetos.append(projeto)
    
    return render_template('projetos.html.j2', projetos=projetos)

@app.route('/adicionar_projeto', methods=['POST'])
@login_required
@admin_required
def adicionar_projeto():
    """Adiciona novo projeto ao calendário"""
    titulo, data_inicio = request.form.get('titulo', '').strip(), request.form.get('data_inicio', '').strip()
    
    if not titulo or not data_inicio:
        flash('Título e data de início são obrigatórios!', 'error')
        return redirect('/calendario')
    
    admin_id = get_user_id('admin')
    with get_db() as conn:
        conn.execute('''INSERT INTO eventos_calendario (titulo, descricao, data_inicio, data_fim, cor, usuario_id)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (titulo, request.form.get('descricao', ''), data_inicio, 
                     request.form.get('data_fim', ''), request.form.get('cor', '#28a745'), admin_id))
    
    flash('Projeto adicionado!', 'success')
    return redirect('/projetos')

@app.route('/editar_projeto', methods=['POST'])
@login_required
@admin_required
def editar_projeto():
    """Edita projeto existente"""
    try:
        projeto_id = int(request.form.get('project_id'))
    except (ValueError, TypeError):
        flash('ID inválido!', 'error')
        return redirect('/calendario')
    
    titulo, data_inicio = request.form.get('titulo', '').strip(), request.form.get('data_inicio', '').strip()
    
    if not titulo or not data_inicio:
        flash('Título e data são obrigatórios!', 'error')
        return redirect('/calendario')
    
    admin_id = get_user_id('admin')
    with get_db() as conn:
        if conn.execute('SELECT 1 FROM eventos_calendario WHERE id = ? AND usuario_id = ?', 
                       (projeto_id, admin_id)).fetchone():
            conn.execute('''UPDATE eventos_calendario SET titulo=?, descricao=?, data_inicio=?, data_fim=?, cor=?
                           WHERE id=? AND usuario_id=?''',
                        (titulo, request.form.get('descricao', ''), data_inicio,
                         request.form.get('data_fim', ''), request.form.get('cor', '#28a745'), projeto_id, admin_id))
            flash('Projeto atualizado!', 'success')
        else:
            flash('Projeto não encontrado!', 'error')
    
    return redirect('/projetos')

@app.route('/excluir_projeto', methods=['POST'])
@login_required
@admin_required
def excluir_projeto():
    """Exclui projeto do calendário"""
    try:
        projeto_id = int(request.form.get('project_id'))
    except (ValueError, TypeError):
        flash('ID inválido!', 'error')
        return redirect('/calendario')
    
    admin_id = get_user_id('admin')
    with get_db() as conn:
        if conn.execute('SELECT 1 FROM eventos_calendario WHERE id = ? AND usuario_id = ?', 
                       (projeto_id, admin_id)).fetchone():
            conn.execute('DELETE FROM eventos_calendario WHERE id = ? AND usuario_id = ?', (projeto_id, admin_id))
            flash('Projeto excluído!', 'success')
        else:
            flash('Projeto não encontrado!', 'error')
    
    return redirect('/projetos')

# ========== SISTEMA DE LOJA ==========

@app.route('/finalizar_compra', methods=['POST'])
@login_required
def finalizar_compra_route():
    """Processa finalização da compra"""
    try:
        dados = request.get_json()
        carrinho = dados.get('carrinho', [])
        endereco = dados.get('endereco', '').strip()
        
        if not carrinho or not endereco:
            return {'success': False, 'message': 'Carrinho vazio ou endereço não informado'}
        
        usuario_id = get_user_id(session['usuario'])
        total = sum(item['preco'] * item['quantidade'] for item in carrinho)
        
        with get_db() as conn:
            # Inserir pedido
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO pedidos (usuario_id, total, endereco, data_pedido) 
                             VALUES (?, ?, ?, ?)''',
                          (usuario_id, total, endereco, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            
            pedido_id = cursor.lastrowid
            
            # Inserir itens do pedido
            for item in carrinho:
                cursor.execute('''INSERT INTO itens_pedido (pedido_id, produto_id, quantidade, preco_unitario)
                                 VALUES (?, ?, ?, ?)''',
                              (pedido_id, item['id'], item['quantidade'], item['preco']))
            
            # Buscar dados do usuário
            usuario = conn.execute('SELECT nome, email FROM usuarios WHERE id = ?', (usuario_id,)).fetchone()
            
            # Preparar dados para email
            itens_texto = '\n'.join([f"- {item['nome']} (x{item['quantidade']}) - R$ {item['preco']:.2f}" 
                                   for item in carrinho])
            
            dados_email = {
                'id': pedido_id,
                'cliente': usuario['nome'],
                'email': usuario['email'],
                'endereco': endereco,
                'itens': itens_texto,
                'total': f"{total:.2f}",
                'data': datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            }
            
            # Enviar email
            if enviar_email_pedido(dados_email):
                return {'success': True, 'message': 'Compra finalizada! Enviaremos o código de pagamento para o seu email'}
            else:
                return {'success': True, 'message': 'Compra registrada! (Email temporariamente indisponível)'}
                
    except Exception as e:
        return {'success': False, 'message': 'Erro ao processar compra'}

# ========== CONFIGURAÇÕES ==========

@app.route('/configurar_tamanho_upload', methods=['POST'])
@login_required
@admin_required
def configurar_tamanho_upload():
    """Configura tamanho máximo de upload de arquivos"""
    global MAX_FILE_SIZE
    try:
        novo_tamanho = int(request.form.get('tamanho_mb', 5))
        if 1 <= novo_tamanho <= 50:
            MAX_FILE_SIZE = novo_tamanho * 1024 * 1024
            flash(f'Tamanho configurado para {novo_tamanho}MB', 'success')
        else:
            flash('Tamanho deve estar entre 1MB e 50MB', 'error')
    except ValueError:
        flash('Valor inválido', 'error')
    
    return redirect('/usuarios')

# ========== CONTEXTO GLOBAL ==========

@app.context_processor
def inject_user():
    """Injeta variáveis globais nos templates"""
    return dict(
        session=session, 
        is_admin=is_admin
    )

# ========== INICIALIZAÇÃO ==========

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
