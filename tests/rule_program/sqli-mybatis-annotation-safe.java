import org.apache.ibatis.annotations.Select;
interface Mapper { @Select("SELECT name FROM users WHERE id=#{id}") String load(String id); }
