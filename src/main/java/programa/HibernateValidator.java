package programa;

import java.util.Set;

/**
 * Demonstra uma validação simples com Hibernate Validator (javax.validation).
 */
public class HibernateValidator{

    static class Usuario {
        @NotBlank
        private String nome;

        @Positive
        private int idade;

        Usuario(String nome, int idade) {
            this.nome = nome;
            this.idade = idade;
        }
    }

    public static void main(String[] args) {
        // Cria o Validator
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();

        // Caso inválido (nome em branco e idade negativa)
        Usuario u = new Usuario("  ", -1);

        // Valida
        Set<ConstraintViolation<Usuario>> violacoes = validator.validate(u);

        // Mostra resultado
        if (violacoes.isEmpty()) {
            System.out.println("OK: sem violações");
        } else {
            System.out.println("Falhas de validação:");
            for (ConstraintViolation<Usuario> v : violacoes) {
                System.out.println(" - " + v.getPropertyPath() + ": " + v.getMessage());
            }
        }

        factory.close();
    }
}
