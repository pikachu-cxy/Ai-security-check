interface Mapper {
// ruleid: ai-security.java.mybatis-annotation
@org.apache.ibatis.annotations.Select("SELECT * FROM users WHERE name='${name}'")
String unsafe(String name);
// ok: ai-security.java.mybatis-annotation
@org.apache.ibatis.annotations.Select("SELECT * FROM users WHERE name=#{name}")
String safe(String name);
}
