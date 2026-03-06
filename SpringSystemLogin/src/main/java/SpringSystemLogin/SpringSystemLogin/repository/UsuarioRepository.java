package SpringSystemLogin.SpringSystemLogin.repository;

import org.springframework.data.repository.CrudRepository;
import SpringSystemLogin.SpringSystemLogin.model.Usuario;

public interface UsuarioRepository extends CrudRepository<Usuario, Long> {

    Usuario findByEmail(String email);

}