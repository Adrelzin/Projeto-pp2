from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "@Darel230109"

livros = []

usuarios = {
    'admin' : "senha2301",
    'darelskidrop' : "livros2025"
}

@app.route('/criar', methods = ['POST'])
def create():
    nome = request.form['nome']
    livros.append(nome)
    return redirect('/index')

@app.route('/alterar', methods=['POST'])
def update():
    old_name = request.form['old_name']
    new_name = request.form['new_name']
    if old_name in livros:
        index = livros.index(old_name)
        livros[index] = new_name
    return redirect('/index')

@app.route('/apagar', methods=['POST'])
def delete():
    nome = request.form['nome']
    if nome in livros:
        livros.remove(nome)
    return redirect('/index')

@app.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        if nome in usuarios and usuarios[nome] == senha:
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
        if nome in usuarios:
            return render_template('cadastro.html', erro='Usuário já existe! Escolha outro nome.')
        usuarios[nome] = senha
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
    return render_template('usuarios.html', usuarios = usuarios)

@app.route('/index')
def index():
    if 'usuario' not in session:
        return redirect('/login')
    return render_template('index.html', livros = livros)

# Rota principal redireciona para cadastro
@app.route('/')
def home():
    return redirect('/cadastro')

if __name__ == '__main__':
    app.run(debug=True)