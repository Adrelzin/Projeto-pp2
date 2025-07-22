from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import re
import os
from PIL import Image
import uuid

app = Flask(__name__)
app.secret_key = "@Darel230109"

# Configurações
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ========== UTILITÁRIOS ==========
def validar_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def processar_imagem(arquivo):
    """Salva e redimensiona imagem"""
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
    if nome_arquivo:
        caminho = os.path.join(UPLOAD_FOLDER, nome_arquivo)
        try:
            if os.path.exists(caminho):
                os.remove(caminho)
        except Exception as e:
            print(f"Erro ao remover imagem: {e}")

def get_db():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_id(nome_usuario):
    """Retorna o ID do usuário"""
    with get_db() as conn:
        user = conn.execute('SELECT id FROM usuarios WHERE nome = ?', (nome_usuario,)).fetchone()
        return user['id'] if user else None

def is_admin():
    """Função para verificar se o usuário atual é admin"""
    return session.get('usuario') == 'admin'

# ========== DECORADORES ==========
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            return redirect('/index')
        return f(*args, **kwargs)
    return decorated

# ========== INICIALIZAÇÃO DB ==========
def init_db():
    with sqlite3.connect('app.db') as conn:
        cursor = conn.cursor()
        
        # Tabelas
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
        
        # Verificar e adicionar colunas se necessário
        def add_column_if_not_exists(table, column, definition):
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]
            if column not in columns:
                cursor.execute(f'ALTER TABLE {table} ADD COLUMN {definition}')
        
        add_column_if_not_exists('usuarios', 'senha_original', 'senha_original TEXT')
        add_column_if_not_exists('usuarios', 'email', 'email TEXT')
        add_column_if_not_exists('noticias', 'data_publicacao', 'data_publicacao TEXT')
        add_column_if_not_exists('plantas', 'imagem', 'imagem TEXT')
        
        # Usuários padrão
        cursor.execute('SELECT COUNT(*) FROM usuarios')
        if cursor.fetchone()[0] == 0:
            users = [
                ('admin', 'admin@sementediaria.com', 'senha2301'),
                ('darelskidrop', 'darel@sementediaria.com', 'livros2025')
            ]
            for nome, email, senha in users:
                cursor.execute('INSERT INTO usuarios (nome, email, senha, senha_original) VALUES (?, ?, ?, ?)',
                             (nome, email, generate_password_hash(senha), senha))

# ========== ROTAS PRINCIPAIS ==========
@app.route('/')
def home():
    return redirect('/index' if 'usuario' in session else '/login')

@app.route('/index')
@login_required
def index():
    return render_template('index.html', usuario=session['usuario'])

@app.route('/redes')
def redes():
    return render_template('redes.html')

@app.route('/ajuda')
def ajuda():
    return render_template('ajuda.html')

@app.route('/servicos')
def servicos():
    return render_template('servicos.html')

# ========== AUTENTICAÇÃO ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
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
    session.pop('usuario', None)
    return redirect('/login')

# ========== PLANTAS ==========
@app.route('/plantas')
@login_required
def plantas():
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
    nome, tipo = request.form.get('nome', '').strip(), request.form.get('tipo', '').strip()
    
    if not nome or not tipo:
        flash('Nome e tipo são obrigatórios!', 'error')
        return redirect('/plantas')
    
    usuario_id = get_user_id(session['usuario'])
    if not usuario_id:
        flash('Usuário não encontrado!', 'error')
        return redirect('/plantas')
    
    # Verificar tamanho do arquivo
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

# ========== NOTÍCIAS (CAMPUS) ==========
@app.route('/campus', methods=['GET', 'POST'])
@login_required
def campus():
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
    with get_db() as conn:
        if conn.execute('SELECT 1 FROM noticias WHERE id = ?', (id,)).fetchone():
            conn.execute('DELETE FROM noticias WHERE id = ?', (id,))
            flash('Notícia excluída!', 'success')
        else:
            flash('Notícia não encontrada!', 'error')
    
    return redirect('/campus')

# ========== USUÁRIOS ==========
@app.route('/usuarios')
@login_required
def listar_usuarios():
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
    if session['usuario'] == nome_usuario:
        flash('Não pode excluir seu próprio usuário!', 'error')
        return redirect('/usuarios')
    
    usuario_id = get_user_id(nome_usuario)
    if not usuario_id:
        flash('Usuário não encontrado!', 'error')
        return redirect('/usuarios')
    
    with get_db() as conn:
        # Remover imagens das plantas
        plantas = conn.execute('SELECT imagem FROM plantas WHERE usuario_id = ?', (usuario_id,)).fetchall()
        for planta in plantas:
            if planta['imagem']:
                remover_imagem(planta['imagem'])
        
        conn.execute('DELETE FROM plantas WHERE usuario_id = ?', (usuario_id,))
        conn.execute('DELETE FROM usuarios WHERE nome = ?', (nome_usuario,))
    
    flash(f'Usuário "{nome_usuario}" excluído!', 'success')
    return redirect('/usuarios')

# ========== PROJETOS/CALENDÁRIO ==========
def get_admin_projects():
    admin_id = get_user_id('admin')
    if not admin_id:
        return []
    
    with get_db() as conn:
        return conn.execute('SELECT * FROM eventos_calendario WHERE usuario_id = ? ORDER BY data_inicio ASC', 
                           (admin_id,)).fetchall()

@app.route('/calendario')
@login_required
def calendario():
    projetos = [dict(p) for p in get_admin_projects()]
    return render_template('calendario.html.j2', projetos=projetos)

@app.route('/projetos')
@login_required
def projetos():
    projetos_raw = get_admin_projects()
    projetos = []
    data_atual = datetime.now()
    
    for p in projetos_raw:
        projeto = dict(p)
        try:
            data_inicio = datetime.strptime(projeto['data_inicio'], '%Y-%m-%d')
            data_fim = datetime.strptime(projeto['data_fim'], '%Y-%m-%d') if projeto['data_fim'] else None
            
            # Determinar status baseado nas datas
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

# ========== CONFIGURAÇÕES ==========
@app.route('/configurar_tamanho_upload', methods=['POST'])
@login_required
@admin_required
def configurar_tamanho_upload():
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
    return dict(
        session=session, 
        is_admin=is_admin
    )

# ========== INICIALIZAÇÃO ==========
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
