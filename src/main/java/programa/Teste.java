package programa;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Teste {

    public static void main(String[] args) {
        
        System.out.println("Iniciando teste com Jackson-databind vulnerável...");

        // Apenas instanciar e usar a classe é o suficiente
        // para que o Maven a considere uma dependência real.
        ObjectMapper mapper = new ObjectMapper();

        try {
            // Criar um JSON simples
            String jsonString = "{\"nome\":\"Teste\"}";
            
            // Tentar "ler" o JSON
            // Este é um uso padrão da biblioteca.
            Object obj = mapper.readValue(jsonString, Object.class);
            
            System.out.println("Objeto deserializado: " + obj.toString());

        } catch (Exception e) {
            System.out.println("Ocorreu um erro no processamento do JSON: " + e.getMessage());
        }

        System.out.println("Teste com Jackson finalizado.");
    }
    
}
