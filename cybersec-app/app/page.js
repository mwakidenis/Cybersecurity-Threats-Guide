import Navbar from '../components/Navbar';
import HeroSection from '../components/HeroSection';
import CategoryGrid from '../components/CategoryGrid';
import Footer from '../components/Footer';

export default function HomePage() {
  return (
    <>
      <Navbar />
      <main>
        <HeroSection />
        <CategoryGrid />
      </main>
      <Footer />
    </>
  );
}
