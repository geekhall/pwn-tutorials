int Pin=8;
void setup() {
  pinMode(Pin,OUTPUT);
}
void fun1()
{
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
}
void fun2()
{
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
}
void fun3()
{
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
}
void fun4()
{
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
}
void fun5()
{
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
}
void fun6()
{
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
}
void fun7()
{
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(500);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
  digitalWrite(Pin, HIGH);
  delay(200);
  digitalWrite(Pin, LOW);
  delay(100);
}
void loop() {
    fun1();
    fun2();
    fun1();
    fun2();
    fun1();
    fun2();
    fun3();
    fun4();
    fun5();

    fun3();
    fun4();
    fun5();

    fun7();
    fun7();

    fun6();
    fun5();

    fun6();
    fun5();
}


