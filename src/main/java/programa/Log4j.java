package programa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4j {
    private static final Logger logger = LogManager.getLogger(Teste.class);

    public static void main(String[] args) {
        System.out.println("Iniciando aplicação de teste de vulnerabilidade...");

        // Usando o logger para garantir que a dependência seja carregada.
        // O código abaixo, em um ambiente vulnerável, poderia ser explorado.
        logger.error("Este é um teste de log com uma dependência vulnerável.");

        System.out.println("Aplicação finalizada.");
    }
}
