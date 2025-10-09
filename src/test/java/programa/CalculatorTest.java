package test.java.programa;

import main.java.programa.Calculator;

public class CalculatorTest {

    @Test
    void add_deveSomarNumeros() {
        Calculator c = new Calculator();
        assertEquals(5, c.add(2, 3));
    }

    private void assertEquals(int i, int j) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'assertEquals'");
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

    private void assertEquals(double d, double divide, double e) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'assertEquals'");
    }
}
