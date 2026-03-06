package SpringSystemLogin.SpringSystemLogin.controller;

import java.io.UnsupportedEncodingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import SpringSystemLogin.SpringSystemLogin.model.Usuario;
import SpringSystemLogin.SpringSystemLogin.repository.UsuarioRepository;
import SpringSystemLogin.SpringSystemLogin.service.CookieService;

@Controller
public class LoginController {
	
	@Autowired
	private UsuarioRepository ur;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@GetMapping("/login")
	public String login() {
		return "login";
	}
	
	@GetMapping("/")
	public String dashboard(Model model, HttpServletRequest request) throws Exception {
		model.addAttribute("nome",CookieService.getCookie(request, "nomeUsuario"));
		return "index";
	}
	
	@PostMapping("/logar")
	public String loginUsuario(Usuario usuarioDigitado,
	                           Model model,
	                           HttpServletResponse response) throws UnsupportedEncodingException {

	    Usuario usuarioBanco = ur.findByEmail(usuarioDigitado.getEmail());

	    if (usuarioBanco != null &&
	    		passwordEncoder.matches(usuarioDigitado.getSenha(),
                        usuarioBanco.getSenha())) {

	        CookieService.setCookie(response, "usuarioId",
	                String.valueOf(usuarioBanco.getId()), 10000);

	        CookieService.setCookie(response, "nomeUsuario",
	                usuarioBanco.getNome(), 10000);

	        return "redirect:/";
	    }

	    model.addAttribute("erro","Usuário ou senha inválidos");
	    return "login";
	}
	
	@GetMapping("/sair")
	public String sair(HttpServletResponse response) throws UnsupportedEncodingException {
			CookieService.setCookie(response, "usuarioId", "", 0);
			CookieService.setCookie(response, "nomeUsuario", "", 0);
			return "redirect:/login";

	}
	
	
	@GetMapping("/cadastroUsuario")
	public String cadastro(Model model) {
	    model.addAttribute("usuario", new Usuario());
	    return "cadastro";
	}
	
	@PostMapping("/cadastroUsuario")
	public String cadastroUsuario(@Valid Usuario usuario, BindingResult result) {
		
		if (ur.findByEmail(usuario.getEmail()) != null) {
		    result.rejectValue("email", "erro.email", "Email já cadastrado");
		}
		
		if (!usuario.getSenha().equals(usuario.getConfirmarSenha())) {
		    result.rejectValue("confirmarSenha", "erro.confirmarSenha", "As senhas não coincidem");
		}
		
		if (result.hasErrors()) {
			return "cadastro";
		}
		
		usuario.setSenha(passwordEncoder.encode(usuario.getSenha()));
		ur.save(usuario);
		return "redirect:/login";
	}
}