from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "@Darel230109"

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Criar tabela de usuários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL
        )
    ''')
    
    # Criar tabela de livros
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS livros (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL
        )
    ''')
    
    # Inserir usuários padrão se não existirem
    cursor.execute('SELECT COUNT(*) FROM usuarios')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO usuarios (nome, senha) VALUES (?, ?)', 
                      ('admin', generate_password_hash('senha2301')))
        cursor.execute('INSERT INTO usuarios (nome, senha) VALUES (?, ?)', 
                      ('darelskidrop', generate_password_hash('livros2025')))
    
    conn.commit()
    conn.close()

# Função para obter conexão com o banco
def get_db_connection():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/criar', methods=['POST'])
def create():
    nome = request.form['nome']
    conn = get_db_connection()
    conn.execute('INSERT INTO livros (nome) VALUES (?)', (nome,))
    conn.commit()
    conn.close()
    return redirect('/index')

@app.route('/alterar', methods=['POST'])
def update():
    old_name = request.form['old_name']
    new_name = request.form['new_name']
    conn = get_db_connection()
    conn.execute('UPDATE livros SET nome = ? WHERE nome = ?', (new_name, old_name))
    conn.commit()
    conn.close()
    return redirect('/index')

@app.route('/apagar', methods=['POST'])
def delete():
    nome = request.form['nome']
    conn = get_db_connection()
    conn.execute('DELETE FROM livros WHERE nome = ?', (nome,))
    conn.commit()
    conn.close()
    return redirect('/index')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        
        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE nome = ?', (nome,)).fetchone()
        conn.close()
        
        if usuario and check_password_hash(usuario['senha'], senha):
            session['usuario'] = nome
            return redirect('/index')
        else:
            return render_template('login.html', erro='Login inválido! Usuário ou senha incorretos.')
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        
        conn = get_db_connection()
        usuario_existente = conn.execute('SELECT * FROM usuarios WHERE nome = ?', (nome,)).fetchone()
        
        if usuario_existente:
            conn.close()
            return render_template('cadastro.html', erro='Usuário já existe! Escolha outro nome.')
        
        # Hash da senha antes de salvar
        senha_hash = generate_password_hash(senha)
        conn.execute('INSERT INTO usuarios (nome, senha) VALUES (?, ?)', (nome, senha_hash))
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect('/cadastro')

@app.route('/usuarios')
def listar_usuarios():
    if 'usuario' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    usuarios = conn.execute('SELECT nome FROM usuarios').fetchall()
    conn.close()
    
    # Converter para formato que o template espera
    usuarios_dict = {usuario['nome']: '****' for usuario in usuarios}
    return render_template('usuarios.html', usuarios=usuarios_dict)

@app.route('/index')
def index():
    if 'usuario' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    livros = conn.execute('SELECT nome FROM livros').fetchall()
    conn.close()
    
    # Converter para lista que o template espera
    livros_list = [livro['nome'] for livro in livros]
    return render_template('index.html', livros=livros_list)

# Rota principal redireciona para cadastro
@app.route('/')
def home():
    return redirect('/cadastro')

if __name__ == '__main__':
    init_db()  # Inicializa o banco ao iniciar a aplicação
    app.run(debug=True)
