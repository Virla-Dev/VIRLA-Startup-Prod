import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  sendPasswordResetEmail,
  sendEmailVerification,
  signOut,
  onAuthStateChanged,
  EmailAuthProvider,
  linkWithCredential,
} from 'firebase/auth'
import { firebaseAuth, googleProvider } from './firebase'

/** Cria conta por e-mail/senha e dispara o e-mail de verificação. */
export async function registerWithEmail(email, senha) {
  if (!firebaseAuth) throw new Error('Firebase Auth não inicializado.')
  const cred = await createUserWithEmailAndPassword(firebaseAuth, email, senha)
  await sendEmailVerification(cred.user)
  return cred.user
}

export async function loginWithEmail(email, senha) {
  if (!firebaseAuth) throw new Error('Firebase Auth não inicializado.')
  const cred = await signInWithEmailAndPassword(firebaseAuth, email, senha)
  return cred.user
}

export async function loginWithGoogle() {
  if (!firebaseAuth) throw new Error('Firebase Auth não inicializado.')
  const cred = await signInWithPopup(firebaseAuth, googleProvider)
  return cred.user
}

export function resetPassword(email) {
  if (!firebaseAuth) throw new Error('Firebase Auth não inicializado.')
  return sendPasswordResetEmail(firebaseAuth, email)
}

export function logout() {
  if (!firebaseAuth) return Promise.resolve()
  return signOut(firebaseAuth)
}

export function resendVerification() {
  if (!firebaseAuth || !firebaseAuth.currentUser) return Promise.resolve()
  return sendEmailVerification(firebaseAuth.currentUser)
}

/** Recarrega o usuário e devolve o estado atual de emailVerified. */
export async function reloadUser() {
  if (!firebaseAuth || !firebaseAuth.currentUser) return false
  await firebaseAuth.currentUser.reload()
  return firebaseAuth.currentUser.emailVerified === true
}

/** ID token atual (renovado pelo SDK). `forceRefresh` recarrega custom claims. */
export function getIdToken(forceRefresh = false) {
  if (!firebaseAuth) return Promise.resolve(null)
  const u = firebaseAuth.currentUser
  return u ? u.getIdToken(forceRefresh) : Promise.resolve(null)
}

export function onAuthChange(cb) {
  if (!firebaseAuth) {
    // Firebase não inicializado (variáveis de ambiente ausentes no build) —
    // notifica o listener como "deslogado" e devolve um unsubscribe vazio
    // para não quebrar quem chama, evitando tela branca por TypeError.
    cb(null)
    return () => {}
  }
  return onAuthStateChanged(firebaseAuth, cb)
}

/** true se a conta atual já possui provedor de e-mail/senha. */
export function hasPasswordProvider() {
  if (!firebaseAuth) return false
  const u = firebaseAuth.currentUser
  return u ? u.providerData.some((p) => p.providerId === 'password') : false
}

/** Vincula uma senha à conta atual (ex.: quem entrou só com Google). */
export async function linkPassword(novaSenha) {
  if (!firebaseAuth) throw new Error('Firebase Auth não inicializado.')
  const u = firebaseAuth.currentUser
  if (!u) throw new Error('Nenhum usuário autenticado.')
  const credential = EmailAuthProvider.credential(u.email, novaSenha)
  await linkWithCredential(u, credential)
}

const MESSAGES = {
  'auth/email-already-in-use': 'Este e-mail já está cadastrado.',
  'auth/invalid-email': 'E-mail inválido.',
  'auth/weak-password': 'A senha deve ter pelo menos 6 caracteres.',
  'auth/too-many-requests': 'Muitas tentativas. Tente novamente em alguns minutos.',
  'auth/network-request-failed': 'Falha de conexão. Verifique sua internet.',
  'auth/invalid-credential': 'Credenciais inválidas.',
  'auth/wrong-password': 'Credenciais inválidas.',
  'auth/user-not-found': 'Credenciais inválidas.',
  'auth/popup-closed-by-user': '',
  'auth/cancelled-popup-request': '',
  'auth/popup-blocked': 'Habilite pop-ups para entrar com o Google.',
  'auth/unauthorized-domain': 'Este domínio não está autorizado para login com Google. Entre em contato com o suporte.',
  'auth/operation-not-allowed': 'Este método de login não está habilitado. Entre em contato com o suporte.',
  'auth/requires-recent-login': 'Faça login novamente para criar sua senha.',
  'auth/credential-already-in-use': 'Esta conta já possui uma senha.',
  'auth/provider-already-linked': 'Esta conta já possui uma senha.',
}

/** Mensagem pt-BR para um código de erro do Firebase Auth. '' = silencioso. */
export function mapAuthError(code) {
  if (code in MESSAGES) return MESSAGES[code]
  return 'Não foi possível concluir. Tente novamente.'
}
