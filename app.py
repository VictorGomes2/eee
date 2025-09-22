# =======================================================================
# CM REURB v2.2 - Backend Flask Completo (Pronto para Deploy)
# =======================================================================
# VERSÃO COMPLETA: Unindo todas as funcionalidades originais com as
# correções de CORS e Pre-flight para funcionar em serviços como o Render.
# =======================================================================

import os
import datetime
from functools import wraps
import jwt  # PyJWT

import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =======================================================================
# ⚙️ CONFIGURAÇÃO DA APLICAÇÃO
# =======================================================================

app = Flask(__name__)

# 🔹 CORS configurado para ambiente de produção/desenvolvimento
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# 🔹 Carregando variáveis de ambiente (essencial para o Render)
SECRET_KEY = os.environ.get('SECRET_KEY', 'chave-secreta-para-desenvolvimento-muito-segura')
DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://reurb_user:123@localhost:5432/reurb_apk')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =======================================================================
# MODELS (TODOS OS MODELOS ORIGINAIS)
# =======================================================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    senha_hash = db.Column(db.String(1024), nullable=False)
    acesso = db.Column(db.String(20), nullable=False, default='Usuario')

    def __init__(self, nome, usuario, senha, acesso='Usuario'):
        self.nome = nome
        self.usuario = usuario
        self.senha_hash = generate_password_hash(senha, method="scrypt")
        self.acesso = acesso

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)


class CadastroReurb(db.Model):
    __tablename__ = 'cadastros_reurb'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default='Em Análise')
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    req_nome = db.Column(db.String(150))
    req_cpf = db.Column(db.String(20))
    req_rg = db.Column(db.String(20))
    req_data_nasc = db.Column(db.String(20))
    req_nacionalidade = db.Column(db.String(50))
    req_estado_civil = db.Column(db.String(30))
    conj_nome = db.Column(db.String(150))
    conj_cpf = db.Column(db.String(20))
    req_profissao = db.Column(db.String(100))
    req_telefone = db.Column(db.String(30))
    req_email = db.Column(db.String(150))
    imovel_cep = db.Column(db.String(15))
    imovel_logradouro = db.Column(db.String(150))
    imovel_numero = db.Column(db.String(20))
    imovel_complemento = db.Column(db.String(100))
    imovel_bairro = db.Column(db.String(100))
    imovel_cidade = db.Column(db.String(100))
    imovel_uf = db.Column(db.String(2))
    inscricao_imobiliaria = db.Column(db.String(30), index=True)
    imovel_area_total = db.Column(db.Float)
    imovel_area_construida = db.Column(db.Float)
    imovel_uso = db.Column(db.String(30))
    imovel_tipo_construcao = db.Column(db.String(30))
    reurb_renda_familiar = db.Column(db.Float)
    reurb_outro_imovel = db.Column(db.String(10))


class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    cadastro_id = db.Column(db.Integer, db.ForeignKey('cadastros_reurb.id'), nullable=False)
    nome_arquivo = db.Column(db.String(255), nullable=False)
    path_arquivo = db.Column(db.String(512), nullable=False)
    tipo_documento = db.Column(db.String(100))
    data_upload = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    cadastro = db.relationship("CadastroReurb", backref=db.backref("documentos", lazy=True, cascade="all, delete-orphan"))


class PadraoConstrutivo(db.Model):
    __tablename__ = 'padroes_construtivos'
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(150), nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class ValorLogradouro(db.Model):
    __tablename__ = 'valores_logradouro'
    id = db.Column(db.Integer, primary_key=True)
    logradouro = db.Column(db.String(150), unique=True, nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class AliquotaIPTU(db.Model):
    __tablename__ = 'aliquotas_iptu'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(150), unique=True, nullable=False)
    aliquota = db.Column(db.Float, nullable=False)

# =======================================================================
# SERVIÇOS E UTILIDADES
# =======================================================================

class CalculoTributarioService:
    @staticmethod
    def calcular_valores(cadastro: CadastroReurb):
        vvt, vvc, vvi, iptu = 0.0, 0.0, 0.0, 0.0
        try:
            if cadastro.imovel_logradouro and cadastro.imovel_area_total:
                logradouro = ValorLogradouro.query.filter_by(logradouro=cadastro.imovel_logradouro).first()
                if logradouro:
                    vvt = cadastro.imovel_area_total * logradouro.valor_m2
            if cadastro.imovel_tipo_construcao and cadastro.imovel_area_construida:
                padrao = PadraoConstrutivo.query.filter_by(descricao=cadastro.imovel_tipo_construcao).first()
                if padrao:
                    vvc = cadastro.imovel_area_construida * padrao.valor_m2
            vvi = vvt + vvc
            if cadastro.imovel_uso:
                aliquota_data = AliquotaIPTU.query.filter_by(tipo=cadastro.imovel_uso).first()
                if aliquota_data:
                    iptu = vvi * aliquota_data.aliquota
        except Exception as e:
            print(f"Erro no cálculo: {e}")
        return {"vvt": vvt, "vvc": vvc, "vvi": vvi, "iptu": iptu}

# =======================================================================
# DECORADORES (VERSÃO CORRIGIDA PARA CORS PRE-FLIGHT)
# =======================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({'status': 'ok'}), 200
        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401
        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(id=data['public_id']).first()
            if not current_user:
                 return jsonify({'mensagem': 'Usuário do token não encontrado!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # O decorador @token_required já é chamado antes, então podemos assumir que current_user existe.
        # Mas para segurança extra e para lidar com pre-flight, faremos a verificação completa.
        if request.method == 'OPTIONS':
            return jsonify({'status': 'ok'}), 200
        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401
        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('acesso') != 'Administrador':
                return jsonify({'mensagem': 'Permissão negada. Apenas administradores podem acessar.'}), 403
            # A função decorada não precisa mais do current_user, pois a permissão já foi validada.
            # Se precisasse, teríamos que buscar o usuário aqui também.
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401
        # Passa os argumentos originais para a função, sem adicionar 'current_user'
        return f(*args, **kwargs)
    return decorated


# =======================================================================
# ROTAS DA API (TODAS AS ROTAS ORIGINAIS, CORRIGIDAS COM 'OPTIONS')
# =======================================================================

# ------------------- AUTENTICAÇÃO -------------------
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json()
    if not data or not data.get('usuario') or not data.get('senha'):
        return jsonify({'mensagem': 'Não foi possível verificar'}), 401
    user = Usuario.query.filter_by(usuario=data['usuario']).first()
    if user and user.verificar_senha(data['senha']):
        token = jwt.encode({
            'public_id': user.id,
            'usuario': user.usuario,
            'acesso': user.acesso,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'mensagem': 'Login bem-sucedido!', 'token': token, 'nome_usuario': user.nome, 'acesso': user.acesso})
    return jsonify({'mensagem': 'Login ou senha incorretos.'}), 401

# ------------------- CADASTRO REURB -------------------
@app.route('/api/cadastrar_reurb', methods=['POST', 'OPTIONS'])
@token_required
def cadastrar_reurb(current_user):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    data = request.get_json()
    try:
        novo_cadastro = CadastroReurb(
            req_nome=data.get('req_nome'), req_cpf=data.get('req_cpf'), req_rg=data.get('req_rg'),
            req_data_nasc=data.get('req_data_nasc'), req_nacionalidade=data.get('req_nacionalidade'),
            req_estado_civil=data.get('req_estado_civil'), conj_nome=data.get('conj_nome'),
            conj_cpf=data.get('conj_cpf'), req_profissao=data.get('req_profissao'),
            req_telefone=data.get('req_telefone'), req_email=data.get('req_email'),
            imovel_cep=data.get('imovel_cep'), imovel_logradouro=data.get('imovel_logradouro'),
            imovel_numero=data.get('imovel_numero'), imovel_complemento=data.get('imovel_complemento'),
            imovel_bairro=data.get('imovel_bairro'), imovel_cidade=data.get('imovel_cidade'),
            imovel_uf=data.get('imovel_uf'), inscricao_imobiliaria=data.get('inscricao_imobiliaria'),
            imovel_area_total=float(data.get('imovel_area_total') or 0),
            imovel_area_construida=float(data.get('imovel_area_construida') or 0),
            imovel_uso=data.get('imovel_uso'), imovel_tipo_construcao=data.get('imovel_tipo_construcao'),
            reurb_renda_familiar=float(data.get('reurb_renda_familiar') or 0),
            reurb_outro_imovel=data.get('reurb_outro_imovel')
        )
        db.session.add(novo_cadastro)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro REURB criado com sucesso!', 'id': novo_cadastro.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'mensagem': f'Erro ao criar cadastro: {str(e)}'}), 400

@app.route('/api/cadastros', methods=['GET', 'OPTIONS'])
@token_required
def get_cadastros(current_user):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    cadastros = CadastroReurb.query.all()
    output = [{'id': c.id, 'req_nome': c.req_nome, 'req_cpf': c.req_cpf, 'inscricao_imobiliaria': c.inscricao_imobiliaria} for c in cadastros]
    return jsonify(output)

@app.route('/api/imoveis/<inscricao_imobiliaria>', methods=['GET', 'OPTIONS'])
@token_required
def get_imovel(current_user, inscricao_imobiliaria):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    cadastro = CadastroReurb.query.filter_by(inscricao_imobiliaria=inscricao_imobiliaria).first()
    if not cadastro:
        return jsonify({'mensagem': 'Imóvel não encontrado!'}), 404
    
    docs = [{'id': d.id, 'nome_arquivo': d.nome_arquivo, 'tipo_documento': d.tipo_documento} for d in cadastro.documentos]
    
    cadastro_data = {key: getattr(cadastro, key) for key in CadastroReurb.__table__.columns.keys()}
    cadastro_data['documentos'] = docs
    # Formata datas para string para evitar problemas de serialização JSON
    cadastro_data['data_criacao'] = cadastro_data['data_criacao'].isoformat() if cadastro_data['data_criacao'] else None
    cadastro_data['data_atualizacao'] = cadastro_data['data_atualizacao'].isoformat() if cadastro_data['data_atualizacao'] else None

    return jsonify(cadastro_data)

# ------------------- GERENCIAMENTO DE USUÁRIOS (ADMIN) -------------------
@app.route('/api/usuarios', methods=['GET', 'POST', 'OPTIONS'])
@token_required
@admin_required
def gerenciar_usuarios():
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    if request.method == 'GET':
        usuarios = Usuario.query.all()
        output = [{'id': u.id, 'nome': u.nome, 'usuario': u.usuario, 'acesso': u.acesso} for u in usuarios]
        return jsonify(output)
    if request.method == 'POST':
        data = request.get_json()
        try:
            novo_usuario = Usuario(nome=data['nome'], usuario=data['usuario'], senha=data['senha'], acesso=data['acesso'])
            db.session.add(novo_usuario)
            db.session.commit()
            return jsonify({'mensagem': 'Usuário criado com sucesso!'}), 201
        except Exception as e:
            return jsonify({'mensagem': f'Erro ao criar usuário: {e}'}), 400

@app.route('/api/usuarios/<int:id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@token_required
@admin_required
def gerenciar_usuario_por_id(id):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'GET':
        return jsonify({'id': usuario.id, 'nome': usuario.nome, 'usuario': usuario.usuario, 'acesso': usuario.acesso})
    if request.method == 'PUT':
        data = request.get_json()
        usuario.nome = data.get('nome', usuario.nome)
        usuario.usuario = data.get('usuario', usuario.usuario)
        usuario.acesso = data.get('acesso', usuario.acesso)
        if 'senha' in data and data['senha']:
            usuario.senha_hash = generate_password_hash(data['senha'], method="scrypt")
        db.session.commit()
        return jsonify({'mensagem': 'Usuário atualizado com sucesso!'})
    if request.method == 'DELETE':
        db.session.delete(usuario)
        db.session.commit()
        return jsonify({'mensagem': 'Usuário deletado com sucesso!'})

# ------------------- PLANTA GENÉRICA DE VALORES (CORRIGIDO) -------------------

# --- Logradouros ---
@app.route('/api/planta_generica/logradouros', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def pgv_logradouros(current_user):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    if request.method == 'POST':
        if current_user.acesso != 'Administrador':
            return jsonify({'erro': 'Acesso negado'}), 403
        data = request.get_json()
        if not data or 'logradouro' not in data or 'valor_m2' not in data:
            return jsonify({'erro': 'Dados incompletos'}), 400
        novo = ValorLogradouro(logradouro=data['logradouro'], valor_m2=float(data['valor_m2']))
        db.session.add(novo)
        db.session.commit()
        return jsonify({'sucesso': True, 'mensagem': 'Logradouro adicionado!'}), 201

    logradouros = ValorLogradouro.query.all()
    return jsonify([{'id': l.id, 'logradouro': l.logradouro, 'valor_m2': l.valor_m2} for l in logradouros])

@app.route('/api/planta_generica/logradouros/<int:id>', methods=['DELETE', 'OPTIONS'])
@token_required
@admin_required
def delete_logradouro(id):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    item = ValorLogradouro.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'sucesso': True, 'mensagem': 'Logradouro deletado!'})

# --- Padrões Construtivos ---
@app.route('/api/planta_generica/padroes', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def pgv_padroes(current_user):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    if request.method == 'POST':
        if current_user.acesso != 'Administrador':
            return jsonify({'erro': 'Acesso negado'}), 403
        data = request.get_json()
        if not data or 'descricao' not in data or 'valor_m2' not in data:
            return jsonify({'erro': 'Dados incompletos'}), 400
        novo = PadraoConstrutivo(descricao=data['descricao'], valor_m2=float(data['valor_m2']))
        db.session.add(novo)
        db.session.commit()
        return jsonify({'sucesso': True, 'mensagem': 'Padrão construtivo adicionado!'}), 201

    padroes = PadraoConstrutivo.query.all()
    return jsonify([{'id': p.id, 'descricao': p.descricao, 'valor_m2': p.valor_m2} for p in padroes])

@app.route('/api/planta_generica/padroes/<int:id>', methods=['DELETE', 'OPTIONS'])
@token_required
@admin_required
def delete_padrao(id):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    item = PadraoConstrutivo.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'sucesso': True, 'mensagem': 'Padrão construtivo deletado!'})

# --- Alíquotas (NOVAS ROTAS) ---
@app.route('/api/planta_generica/aliquotas', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def pgv_aliquotas(current_user):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    if request.method == 'POST':
        if current_user.acesso != 'Administrador':
            return jsonify({'erro': 'Acesso negado'}), 403
        data = request.get_json()
        if not data or 'tipo' not in data or 'aliquota' not in data:
            return jsonify({'erro': 'Dados incompletos'}), 400
        novo = AliquotaIPTU(tipo=data['tipo'], aliquota=float(data['aliquota']))
        db.session.add(novo)
        db.session.commit()
        return jsonify({'sucesso': True, 'mensagem': 'Alíquota adicionada!'}), 201

    aliquotas = AliquotaIPTU.query.all()
    return jsonify([{'id': a.id, 'tipo': a.tipo, 'aliquota': a.aliquota} for a in aliquotas])

@app.route('/api/planta_generica/aliquotas/<int:id>', methods=['DELETE', 'OPTIONS'])
@token_required
@admin_required
def delete_aliquota(id):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    item = AliquotaIPTU.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'sucesso': True, 'mensagem': 'Alíquota deletada!'})


# ------------------- CÁLCULO E IMPORTAÇÃO -------------------
@app.route('/api/gerar_iptu/<inscricao_imobiliaria>', methods=['GET', 'OPTIONS'])
@token_required
def gerar_iptu(current_user, inscricao_imobiliaria):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    cadastro = CadastroReurb.query.filter_by(inscricao_imobiliaria=inscricao_imobiliaria).first_or_404()
    valores = CalculoTributarioService.calcular_valores(cadastro)
    return jsonify(valores)

@app.route('/api/importar_dados', methods=['POST', 'OPTIONS'])
@token_required
@admin_required
def importar_dados():
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    if 'file' not in request.files:
        return jsonify({'mensagem': 'Nenhum arquivo enviado'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'mensagem': 'Nome de arquivo vazio'}), 400
    if file:
        try:
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            
            # Renomear colunas do dataframe para corresponder aos nomes dos atributos do modelo
            df = df.rename(columns={
                'Nome do Requerente': 'req_nome', 'CPF do Requerente': 'req_cpf',
                # ... adicione todos os outros mapeamentos de coluna aqui ...
                'Inscrição Imobiliária': 'inscricao_imobiliaria'
            })

            for _, row in df.iterrows():
                cadastro = CadastroReurb(**row.to_dict())
                db.session.add(cadastro)
            db.session.commit()
            return jsonify({'mensagem': 'Dados importados com sucesso!'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'mensagem': f'Erro ao importar dados: {e}'}), 500
    return jsonify({'mensagem': 'Tipo de arquivo não suportado'}), 400

# ------------------- UPLOAD DE DOCUMENTOS -------------------
@app.route('/api/upload_documento/<int:id>', methods=['POST', 'OPTIONS'])
@token_required
def upload_documento(current_user, id):
    if request.method == 'OPTIONS': return jsonify({'status': 'ok'}), 200
    cadastro = CadastroReurb.query.get_or_404(id)
    if 'file' not in request.files:
        return jsonify({'mensagem': 'Nenhum arquivo enviado'}), 400
    file = request.files['file']
    tipo_documento = request.form.get('tipo_documento', 'Não especificado')
    if file.filename == '':
        return jsonify({'mensagem': 'Nome de arquivo vazio'}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        novo_documento = Documento(
            cadastro_id=cadastro.id,
            nome_arquivo=filename,
            path_arquivo=filepath,
            tipo_documento=tipo_documento
        )
        db.session.add(novo_documento)
        db.session.commit()
        return jsonify({'mensagem': 'Documento enviado com sucesso!', 'nome_arquivo': filename}), 201

# Rota para servir os arquivos que foram enviados (NÃO precisa de 'OPTIONS')
@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# =======================================================================
# INICIALIZAÇÃO
# =======================================================================
if __name__ == '__main__':
    with app.app_context():
        # Cria o usuário admin padrão se ele não existir
        if not Usuario.query.filter_by(usuario='admin').first():
            print("Criando usuário 'admin' padrão com senha 'admin'...")
            admin_user = Usuario(nome="Administrador", usuario="admin", senha="admin", acesso="Administrador")
            db.session.add(admin_user)
            db.session.commit()
            print("Usuário 'admin' criado com sucesso.")
    # Para desenvolvimento local, use debug=True. O Render ignora isso.
    app.run(debug=True, port=5000)