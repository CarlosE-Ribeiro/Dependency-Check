package test.java.programa;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals; // import estático

public class CalculatorTest {

    @Test
    void add_deveSomarNumeros() {
        Calculator c = new Calculator();
        assertEquals(5, c.add(2, 3));
    }

    @Test
    void subtract_deveSubtrair() {
        Calculator c = new Calculator();
        assertEquals(-1, c.subtract(2, 3));
    }

    @Test
    void multiply_deveMultiplicar() {
        Calculator c = new Calculator();
        assertEquals(6, c.multiply(2, 3));
    }

    @Test
    void divide_deveDividir() {
        Calculator c = new Calculator();
        assertEquals(2.5, c.divide(5, 2), 1e-4); // delta como terceiro argumento
    }
}
