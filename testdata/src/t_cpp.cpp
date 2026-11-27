#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <numeric>
#include <memory>
#include <stdexcept>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <typeinfo>
#include <cmath>

struct Shape { virtual ~Shape() = default; virtual double area() const = 0; virtual std::string name() const = 0; };
struct Circle : Shape { double r; explicit Circle(double r) : r(r) {} double area() const override { return 3.14159265 * r * r; } std::string name() const override { return "circle"; } };
struct Rect : Shape { double w, h; Rect(double w, double h) : w(w), h(h) {} double area() const override { return w * h; } std::string name() const override { return "rect"; } };
struct MyErr : std::runtime_error { int code; MyErr(const std::string& m, int c) : std::runtime_error(m), code(c) {} };
static int dtors = 0;
struct Guard { int id; Guard(int i) : id(i) {} ~Guard() { dtors++; } };
void thrower(int depth) { Guard g(depth); if (depth == 0) throw MyErr("deep failure", 77); thrower(depth - 1); }

int main() {
    std::cout << "== iostream ==" << std::endl;
    std::cout << "int " << 42 << " double " << 3.5 << " hex " << std::hex << 255 << std::dec << " bool " << std::boolalpha << true << "\n";
    std::cout << std::setw(8) << std::setfill('*') << 123 << " " << std::fixed << std::setprecision(3) << 2.0 / 3.0 << "\n";
    std::ostringstream os; os << "built " << 1 << '+' << 2.25; std::cout << os.str() << "\n";
    std::istringstream is("10 20 30 hello"); int x, y, z; std::string word; is >> x >> y >> z >> word;
    std::cout << x + y + z << " " << word << "\n";
    std::cout << "== containers ==" << std::endl;
    std::vector<int> v(20); std::iota(v.begin(), v.end(), 1);
    std::reverse(v.begin(), v.end()); std::sort(v.begin(), v.begin() + 10);
    std::cout << "sum " << std::accumulate(v.begin(), v.end(), 0) << " first " << v[0] << " last " << v.back() << "\n";
    std::map<std::string, int> m{{"one", 1}, {"two", 2}, {"three", 3}}; m["four"] = 4;
    for (auto& kv : m) std::cout << kv.first << "=" << kv.second << " "; std::cout << "\n";
    std::unordered_map<int, std::string> um; for (int i = 0; i < 1000; i++) um[i] = std::to_string(i * i);
    std::cout << "um " << um.size() << " " << um[31] << "\n";
    std::set<std::string> s{"pear", "apple", "fig"}; for (auto& e : s) std::cout << e << " "; std::cout << "\n";
    std::string str = "The quick brown fox"; std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    std::cout << str << " find=" << str.find("BROWN") << " sub=" << str.substr(4, 5) << "\n";
    std::cout << "== polymorphism ==" << std::endl;
    std::vector<std::unique_ptr<Shape>> shapes; shapes.push_back(std::make_unique<Circle>(2)); shapes.push_back(std::make_unique<Rect>(3, 4));
    for (auto& sh : shapes) std::cout << sh->name() << " " << std::setprecision(2) << sh->area() << " typeid=" << (typeid(*sh) == typeid(Circle) ? "Circle" : "other") << "\n";
    Shape* sp = shapes[1].get(); std::cout << "dynamic_cast " << (dynamic_cast<Rect*>(sp) != nullptr) << (dynamic_cast<Circle*>(sp) != nullptr) << "\n";
    std::function<int(int)> sq = [](int a) { return a * a; }; std::cout << "lambda " << sq(12) << "\n";
    std::shared_ptr<int> sp1 = std::make_shared<int>(5); { auto sp2 = sp1; std::cout << "use_count " << sp1.use_count() << "\n"; }
    std::cout << "== exceptions ==" << std::endl;
    try { thrower(5); } catch (const MyErr& e) { std::cout << "caught " << e.what() << " code " << e.code << " dtors " << dtors << "\n"; }
    try { std::vector<int> t(3); t.at(10) = 1; } catch (const std::out_of_range& e) { std::cout << "out_of_range ok\n"; }
    try { throw 42; } catch (int n) { std::cout << "int " << n << "\n"; }
    try { try { throw std::string("inner"); } catch (std::string& s2) { std::cout << "rethrow " << s2 << "\n"; throw; } } catch (...) { std::cout << "outer catch-all\n"; }
    try { std::stoi("not a number"); } catch (const std::invalid_argument&) { std::cout << "stoi invalid\n"; }
    std::cout << "== threads ==" << std::endl;
    std::atomic<int> counter{0}; std::mutex mu; long total = 0;
    std::vector<std::thread> ts;
    for (int t = 0; t < 4; t++) ts.emplace_back([&, t] { for (int i = 0; i < 1000; i++) { counter++; std::lock_guard<std::mutex> lk(mu); total += t; } });
    for (auto& t : ts) t.join();
    std::cout << "counter " << counter << " total " << total << "\n";
    auto t0 = std::chrono::steady_clock::now(); std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    std::cout << "slept_ok " << (ms >= 15 && ms < 2000) << "\n";
    std::cout << "== fstream ==" << std::endl;
    { std::ofstream f("winemu_cpp.txt"); f << "alpha 1\nbeta 2\n"; }
    { std::ifstream f("winemu_cpp.txt"); std::string a; int n; int tot = 0; while (f >> a >> n) tot += n; std::cout << "file total " << tot << "\n"; }
    std::remove("winemu_cpp.txt");
    std::cout << "done" << std::endl;
    return 0;
}
