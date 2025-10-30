package programa;

// Importa as novas dependências
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.TransformedMap;
import java.util.HashMap;
import java.util.Map;

/**
 * Esta classe agora usa o TransformedMap do Apache Commons Collections
 * para validar que a dependência foi carregada.
 * A própria existência desta classe (e da biblioteca) é o que 
 * causa a vulnerabilidade de desserialização (gadget chain).
 */
public class Teste {

    public static void main(String[] args) {
        
        System.out.println("Iniciando teste com Commons Collections vulnerável...");

        // Definindo um "Transformer" simples (apenas para o código compilar)
        Transformer transformer = new Transformer() {
            @Override
            public Object transform(Object input) {
                return ((String) input).toUpperCase();
            }
        };

        // Criando um Map que usa o Transformer
        // Esta é uma das classes usadas nos "gadgets" de desserialização
        Map<String, String> myMap = new HashMap<>();
        Map<String, String> transformedMap = TransformedMap.decorate(myMap, null, transformer);

        // Usando o Map
        transformedMap.put("key", "value");
        
        System.out.println("Valor transformado: " + transformedMap.get("key"));
        System.out.println("Teste com Commons Collections finalizado.");
    }
}
